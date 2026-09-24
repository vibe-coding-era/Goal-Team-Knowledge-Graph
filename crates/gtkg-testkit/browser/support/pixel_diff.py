#!/usr/bin/env python3
"""Deterministic PNG pixel diff for GTKG browser evidence.

The runner intentionally uses only the Python standard library. It accepts
8-bit, non-interlaced RGB and RGBA PNGs and implements all five PNG scanline
filters.
"""

import argparse
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import struct
import sys
import zlib


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_WIDTH = 16_384
DEFAULT_MAX_HEIGHT = 16_384
DEFAULT_MAX_PIXELS = 4_500_000
DEFAULT_MAX_IDAT_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_CHANGED_PIXELS = 1_500_000
DEFAULT_MAX_CLUSTER_PIXELS = 1_500_000
EVIDENCE_EXACT_SET = {
    "diff/before-vs-codex-style.metrics.json",
    "diff/before-vs-codex-style.png",
    "diff/desktop-self-replay.metrics.json",
    "diff/desktop-self-replay.png",
    "e2e/browser-fixture-receipt.json",
    "e2e/codex-wiki-e2e.json",
    "generated/desktop-collapsed.png",
    "generated/desktop-initial-replay.png",
    "generated/desktop-initial.png",
    "generated/desktop-resized.png",
    "generated/desktop-search.png",
    "generated/desktop-selected.png",
    "generated/mobile-closed-focus.png",
    "generated/mobile-drawer-open.png",
    "generated/mobile-initial.png",
    "source/wiki-before-desktop.png",
    "source/wiki-before-mobile.png",
}
_after_publish_file_hook = lambda relative: None


class Budgets:
    def __init__(
        self,
        file_bytes,
        width,
        height,
        pixels,
        idat_bytes,
        decompressed_bytes,
        changed_pixels,
        cluster_pixels,
    ):
        self.file_bytes = file_bytes
        self.width = width
        self.height = height
        self.pixels = pixels
        self.idat_bytes = idat_bytes
        self.decompressed_bytes = decompressed_bytes
        self.changed_pixels = changed_pixels
        self.cluster_pixels = cluster_pixels


def _paeth(left, above, upper_left):
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def _read_chunks(payload):
    if not payload.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG file")
    offset = len(PNG_SIGNATURE)
    while offset < len(payload):
        if offset + 12 > len(payload):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        chunk_type = payload[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(payload):
            raise ValueError("truncated PNG chunk payload")
        chunk_data = payload[data_start:data_end]
        expected_crc = struct.unpack(">I", payload[data_end:crc_end])[0]
        actual_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"invalid PNG CRC for {chunk_type!r}")
        yield chunk_type, chunk_data
        offset = crc_end
        if chunk_type == b"IEND":
            if offset != len(payload):
                raise ValueError("bytes found after PNG IEND")
            return
    raise ValueError("PNG has no IEND chunk")


def _reject_symlink_components(path):
    absolute = Path(os.path.abspath(os.fspath(path)))
    for system_alias in (Path("/var"), Path("/tmp")):
        if absolute != system_alias and system_alias in absolute.parents:
            try:
                alias_mode = os.lstat(system_alias).st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(alias_mode):
                alias_target = Path(os.path.realpath(system_alias))
                absolute = alias_target.joinpath(*absolute.relative_to(system_alias).parts)
            break
    for component in (absolute, *absolute.parents):
        try:
            mode = os.lstat(component).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink path component is forbidden: {component}")
    return absolute


def _input_path(path, budget):
    absolute = _reject_symlink_components(path)
    try:
        details = os.stat(absolute, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError(f"input file is missing: {absolute}") from error
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"input is not a regular file: {absolute}")
    if details.st_size > budget.file_bytes:
        raise ValueError(f"file budget exceeded: {details.st_size} > {budget.file_bytes}")
    return absolute


class OutputTarget:
    def __init__(self, directory_fd, leaf, display_path):
        self.directory_fd = directory_fd
        self.leaf = leaf
        self.display_path = display_path

    def close(self):
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None


def _open_output_target(path):
    absolute = _reject_symlink_components(path)
    if absolute.exists() or absolute.is_symlink():
        raise ValueError(f"output path already exists: {absolute}")
    absolute.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(absolute.parent)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = os.open(absolute.parent, flags)
    try:
        details = os.fstat(directory_fd)
        if not stat.S_ISDIR(details.st_mode):
            raise ValueError(f"output parent is not a directory: {absolute.parent}")
        try:
            os.stat(absolute.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError(f"output path already exists: {absolute}")
        return OutputTarget(directory_fd, absolute.name, absolute)
    except BaseException:
        os.close(directory_fd)
        raise


def _prepare_outputs(
    baseline_path,
    candidate_path,
    diff_path,
    metrics_path,
    identity_transaction=None,
):
    if identity_transaction is None:
        baseline = _reject_symlink_components(baseline_path)
        candidate = _reject_symlink_components(candidate_path)
        diff = _reject_symlink_components(diff_path)
        metrics = _reject_symlink_components(metrics_path)
    else:
        baseline = identity_transaction.normalize_path(baseline_path)
        candidate = identity_transaction.normalize_path(candidate_path)
        diff = identity_transaction.normalize_output_path(diff_path, {"diff"})
        metrics = identity_transaction.normalize_output_path(metrics_path, {"diff"})
    if diff == metrics:
        raise ValueError("diff and metrics paths alias")
    for output in (diff, metrics):
        output_parent = output.parent
        for input_path in (baseline, candidate):
            if input_path == output_parent or output_parent in input_path.parents:
                raise ValueError(f"output root overlaps input root: {output_parent}")
    diff_target = (
        _open_output_target(diff)
        if identity_transaction is None
        else identity_transaction.open_output_target(diff)
    )
    try:
        metrics_target = (
            _open_output_target(metrics)
            if identity_transaction is None
            else identity_transaction.open_output_target(metrics)
        )
    except BaseException:
        diff_target.close()
        raise
    return diff_target, metrics_target


def _stage_bytes(target, payload, label):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary = None
    descriptor = None
    try:
        for attempt in range(32):
            temporary = f".{target.leaf}.tmp-{os.getpid()}-{label}-{attempt}"
            try:
                descriptor = os.open(
                    temporary,
                    flags,
                    0o600,
                    dir_fd=target.directory_fd,
                )
                break
            except FileExistsError:
                continue
        if descriptor is None:
            raise ValueError("exclusive output staging budget exhausted")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short output write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        return temporary
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=target.directory_fd)
            except FileNotFoundError:
                pass
        raise


def _publish_outputs(diff_target, metrics_target, diff_payload, metrics_payload):
    diff_temporary = _stage_bytes(diff_target, diff_payload, "diff")
    metrics_temporary = None
    try:
        metrics_temporary = _stage_bytes(metrics_target, metrics_payload, "metrics")
        os.rename(
            diff_temporary,
            diff_target.leaf,
            src_dir_fd=diff_target.directory_fd,
            dst_dir_fd=diff_target.directory_fd,
        )
        diff_temporary = None
        os.rename(
            metrics_temporary,
            metrics_target.leaf,
            src_dir_fd=metrics_target.directory_fd,
            dst_dir_fd=metrics_target.directory_fd,
        )
        metrics_temporary = None
        os.fsync(diff_target.directory_fd)
        if metrics_target.directory_fd != diff_target.directory_fd:
            os.fsync(metrics_target.directory_fd)
    finally:
        for target, temporary in (
            (diff_target, diff_temporary),
            (metrics_target, metrics_temporary),
        ):
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=target.directory_fd)
                except FileNotFoundError:
                    pass


def read_png(path, budget, identity_transaction=None):
    if identity_transaction is not None and identity_transaction.contains_output_path(path):
        payload = identity_transaction.read_output_file(path, budget.file_bytes)
    else:
        path = _input_path(path, budget)
        payload = path.read_bytes()
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    saw_header = False
    saw_end = False
    for chunk_type, chunk_data in _read_chunks(payload):
        if chunk_type == b"IHDR":
            if saw_header or len(chunk_data) != 13:
                raise ValueError("invalid PNG IHDR")
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", chunk_data
            )
            saw_header = True
            if width == 0 or height == 0:
                raise ValueError("PNG dimensions must be non-zero")
            if width > budget.width:
                raise ValueError(f"width budget exceeded: {width} > {budget.width}")
            if height > budget.height:
                raise ValueError(f"height budget exceeded: {height} > {budget.height}")
            if width * height > budget.pixels:
                raise ValueError(f"pixel budget exceeded: {width * height} > {budget.pixels}")
            if bit_depth != 8 or color_type not in (2, 6):
                raise ValueError("only 8-bit RGB/RGBA PNGs are supported")
            if compression != 0 or filtering != 0 or interlace != 0:
                raise ValueError("unsupported PNG compression/filter/interlace method")
        elif chunk_type == b"IDAT":
            if not saw_header:
                raise ValueError("PNG IDAT precedes IHDR")
            compressed.extend(chunk_data)
            if len(compressed) > budget.idat_bytes:
                raise ValueError(
                    f"IDAT budget exceeded: {len(compressed)} > {budget.idat_bytes}"
                )
        elif chunk_type == b"IEND":
            saw_end = True

    if not saw_header or not saw_end or not compressed:
        raise ValueError("PNG is missing IHDR, IDAT, or IEND")
    channels = 3 if color_type == 2 else 4
    row_bytes = width * channels
    expected_size = height * (row_bytes + 1)
    if expected_size > budget.decompressed_bytes:
        raise ValueError(
            f"decompression budget exceeded: {expected_size} > {budget.decompressed_bytes}"
        )
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(bytes(compressed), budget.decompressed_bytes + 1)
    if len(raw) > budget.decompressed_bytes or decompressor.unconsumed_tail:
        raise ValueError("decompression budget exceeded")
    raw += decompressor.flush(budget.decompressed_bytes + 1 - len(raw))
    if len(raw) > budget.decompressed_bytes:
        raise ValueError("decompression budget exceeded")
    if not decompressor.eof or decompressor.unused_data:
        raise ValueError("invalid or trailing zlib stream")
    if len(raw) != expected_size:
        raise ValueError(f"unexpected PNG data size: {len(raw)} != {expected_size}")

    rows = []
    previous = bytearray(row_bytes)
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        encoded = raw[cursor : cursor + row_bytes]
        cursor += row_bytes
        decoded = bytearray(row_bytes)
        for index, value in enumerate(encoded):
            left = decoded[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = _paeth(left, above, upper_left)
            else:
                raise ValueError(f"unsupported PNG scanline filter: {filter_type}")
            decoded[index] = (value + predictor) & 0xFF
        rows.append(bytes(decoded))
        previous = decoded

    rgba = bytearray(width * height * 4)
    destination = 0
    for row in rows:
        for source in range(0, len(row), channels):
            rgba[destination : destination + 3] = row[source : source + 3]
            rgba[destination + 3] = row[source + 3] if channels == 4 else 255
            destination += 4
    return width, height, bytes(rgba), channels == 4


def _chunk(chunk_type, data):
    crc = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _rgb_png_bytes(width, height, pixels):
    if len(pixels) != width * height * 3:
        raise ValueError("RGB payload size does not match dimensions")
    scanlines = bytearray()
    row_bytes = width * 3
    for row_index in range(height):
        scanlines.append(0)
        start = row_index * row_bytes
        scanlines.extend(pixels[start : start + row_bytes])
    payload = bytearray(PNG_SIGNATURE)
    payload.extend(_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
    payload.extend(_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)))
    payload.extend(_chunk(b"IEND", b""))
    return bytes(payload)


def write_rgb_png(path, width, height, pixels):
    Path(path).write_bytes(_rgb_png_bytes(width, height, pixels))


def _clusters(changed_mask, width, height, cluster_budget):
    cluster_count = 0
    largest = 0
    for start in range(len(changed_mask)):
        if not changed_mask[start]:
            continue
        cluster_count += 1
        changed_mask[start] = 0
        stack = [start]
        area = 0
        while stack:
            point = stack.pop()
            area += 1
            if area > cluster_budget:
                raise ValueError(f"cluster budget exceeded: {area} > {cluster_budget}")
            x = point % width
            y = point // width
            for next_x, next_y in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
                if 0 <= next_x < width and 0 <= next_y < height:
                    neighbor = next_y * width + next_x
                    if changed_mask[neighbor]:
                        changed_mask[neighbor] = 0
                        stack.append(neighbor)
        largest = max(largest, area)
    return cluster_count, largest


def compare(
    baseline_path,
    candidate_path,
    diff_path,
    metrics_path,
    threshold,
    max_ratio,
    max_mae,
    budget,
    identity_transaction=None,
):
    diff_target, metrics_target = _prepare_outputs(
        baseline_path,
        candidate_path,
        diff_path,
        metrics_path,
        identity_transaction,
    )
    try:
        baseline_width, baseline_height, baseline, baseline_has_alpha = read_png(
            baseline_path, budget, identity_transaction
        )
        candidate_width, candidate_height, candidate, candidate_has_alpha = read_png(
            candidate_path, budget, identity_transaction
        )
        width = min(baseline_width, candidate_width)
        height = min(baseline_height, candidate_height)
        if width == 0 or height == 0:
            raise ValueError("PNG comparison has no overlapping pixels")

        changed_mask = bytearray(width * height)
        changed_count = 0
        diff_pixels = bytearray(width * height * 3)
        absolute_sum = 0
        squared_sum = 0
        max_delta = 0
        min_x = width
        min_y = height
        max_x = max_y = -1
        for y in range(height):
            baseline_row = y * baseline_width * 4
            candidate_row = y * candidate_width * 4
            for x in range(width):
                baseline_offset = baseline_row + x * 4
                candidate_offset = candidate_row + x * 4
                compared_channels = 4 if baseline_has_alpha or candidate_has_alpha else 3
                deltas = [
                    abs(
                        baseline[baseline_offset + channel]
                        - candidate[candidate_offset + channel]
                    )
                    for channel in range(compared_channels)
                ]
                absolute_sum += sum(deltas)
                squared_sum += sum(delta * delta for delta in deltas)
                pixel_delta = max(deltas)
                max_delta = max(max_delta, pixel_delta)
                output_offset = (y * width + x) * 3
                if pixel_delta > threshold:
                    point = y * width + x
                    changed_mask[point] = 1
                    changed_count += 1
                    if changed_count > budget.changed_pixels:
                        raise ValueError(
                            f"changed-pixel budget exceeded: {changed_count} > {budget.changed_pixels}"
                        )
                    min_x = min(min_x, x)
                    min_y = min(min_y, y)
                    max_x = max(max_x, x)
                    max_y = max(max_y, y)
                    diff_pixels[output_offset : output_offset + 3] = bytes(
                        (255, min(255, pixel_delta * 2), 0)
                    )
                else:
                    level = sum(candidate[candidate_offset : candidate_offset + 3]) // 9
                    diff_pixels[output_offset : output_offset + 3] = bytes(
                        (level, level, level)
                    )

        total_pixels = width * height
        channel_count = total_pixels * (
            4 if baseline_has_alpha or candidate_has_alpha else 3
        )
        ratio = changed_count / total_pixels
        mae = absolute_sum / channel_count
        rmse = math.sqrt(squared_sum / channel_count)
        cluster_count, largest_cluster = _clusters(
            changed_mask, width, height, budget.cluster_pixels
        )
        same_size = (baseline_width, baseline_height) == (
            candidate_width,
            candidate_height,
        )
        passed = same_size and ratio <= max_ratio and mae <= max_mae
        metrics = {
            "baseline_size": [baseline_width, baseline_height],
            "candidate_size": [candidate_width, candidate_height],
            "comparison_size": [width, height],
            "total_pixels": total_pixels,
            "changed_pixels": changed_count,
            "pixel_diff_ratio": ratio,
            "mean_absolute_error": mae,
            "root_mean_squared_error": rmse,
            "max_channel_delta": max_delta,
            "diff_bbox": None if changed_count == 0 else [min_x, min_y, max_x, max_y],
            "cluster_count": cluster_count,
            "largest_cluster_area": largest_cluster,
            "largest_cluster_ratio": largest_cluster / total_pixels,
            "per_channel_threshold": threshold,
            "thresholds": {"max_diff_ratio": max_ratio, "max_mae": max_mae},
            "passed": passed,
            "diff_path": diff_target.leaf,
        }
        diff_payload = _rgb_png_bytes(width, height, diff_pixels)
        metrics_payload = (json.dumps(metrics, indent=2) + "\n").encode("utf-8")
        _publish_outputs(
            diff_target,
            metrics_target,
            diff_payload,
            metrics_payload,
        )
        if identity_transaction is not None:
            identity_transaction.verify_output_payload(diff_path, diff_payload)
            identity_transaction.verify_output_payload(metrics_path, metrics_payload)
        return passed
    finally:
        diff_target.close()
        metrics_target.close()


def _relative_under(repo_root, target):
    repo = _reject_symlink_components(repo_root)
    target = _reject_symlink_components(target)
    try:
        relative = target.relative_to(repo)
    except ValueError as error:
        raise ValueError(f"root containment budget rejected: {target}") from error
    if not relative.parts:
        raise ValueError("repository root cannot be used as an output root")
    return repo, target, relative


def _secure_directory(repo_root, target, create):
    repo, target, relative = _relative_under(repo_root, target)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(repo, flags)
    try:
        for component in relative.parts:
            try:
                details = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise ValueError(f"required directory is missing: {target}")
                os.mkdir(component, 0o755, dir_fd=descriptor)
                details = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode):
                raise ValueError(f"unsafe root component: {component}")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def prepare_roots(repo_root, output_root, publish_root):
    repo, output, _ = _relative_under(repo_root, output_root)
    _, publish, _ = _relative_under(repo, publish_root)
    if output == publish or output in publish.parents or publish in output.parents:
        raise ValueError("output and publish roots overlap")
    output_fd = _secure_directory(repo, output, True)
    publish_fd = None
    try:
        publish_fd = _secure_directory(repo, publish, True)
    finally:
        os.close(output_fd)
        if publish_fd is not None:
            os.close(publish_fd)
    for directory in ("generated", "diff", "e2e"):
        descriptor = _secure_directory(repo, output / directory, True)
        os.close(descriptor)
    for directory in ("source", "generated", "diff", "e2e"):
        descriptor = _secure_directory(repo, publish / directory, True)
        os.close(descriptor)
    identities = {}
    for name, path in (
        ("root", output),
        ("generated", output / "generated"),
        ("diff", output / "diff"),
        ("e2e", output / "e2e"),
    ):
        descriptor = _secure_directory(repo, path, False)
        try:
            details = os.fstat(descriptor)
            identities[name] = [details.st_dev, details.st_ino]
        finally:
            os.close(descriptor)
    token = {
        "repo_root": str(repo),
        "output_root": str(output.relative_to(repo)),
        "identities": identities,
    }
    encoded = binascii.b2a_base64(
        json.dumps(token, separators=(",", ":")).encode("utf-8"), newline=False
    )
    sys.stdout.buffer.write(encoded + b"\n")


def _decode_identity_token(token):
    try:
        value = json.loads(binascii.a2b_base64(token, strict_mode=True))
    except (ValueError, binascii.Error, json.JSONDecodeError) as error:
        raise ValueError("invalid output identity token") from error
    if set(value) != {"repo_root", "output_root", "identities"}:
        raise ValueError("invalid output identity token shape")
    return value


def _identity_pair(descriptor):
    details = os.fstat(descriptor)
    return [details.st_dev, details.st_ino]


def _open_child_directory(parent_fd, leaf):
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(leaf, flags, dir_fd=parent_fd)
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        os.close(descriptor)
        raise ValueError(f"output identity child is not a directory: {leaf}")
    return descriptor


class OutputIdentityTransaction:
    DIRECTORIES = ("generated", "diff", "e2e")

    def __init__(self, repo_root, identity_token):
        token = _decode_identity_token(identity_token)
        repo = _reject_symlink_components(repo_root)
        if str(repo) != token["repo_root"]:
            raise ValueError("output identity repo mismatch")
        if set(token["identities"]) != {"root", *self.DIRECTORIES}:
            raise ValueError("invalid output identity directory set")
        _, output, _ = _relative_under(repo, repo / token["output_root"])
        self.repo = repo
        self.output = output
        self.token = token
        self.descriptors = {}
        try:
            root_fd = _secure_directory(repo, output, False)
            self.descriptors["root"] = root_fd
            if _identity_pair(root_fd) != token["identities"]["root"]:
                raise ValueError("output root identity mismatch")
            for directory in self.DIRECTORIES:
                descriptor = _open_child_directory(root_fd, directory)
                self.descriptors[directory] = descriptor
                if _identity_pair(descriptor) != token["identities"][directory]:
                    raise ValueError("output subdirectory identity mismatch")
        except BaseException:
            self.close()
            raise

    def close(self):
        for descriptor in self.descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.descriptors = {}

    def normalize_path(self, path):
        absolute = Path(os.path.abspath(os.fspath(path)))
        for system_alias in (Path("/var"), Path("/tmp")):
            if absolute != system_alias and system_alias in absolute.parents:
                try:
                    alias_mode = os.lstat(system_alias).st_mode
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(alias_mode):
                    absolute = Path(os.path.realpath(system_alias)).joinpath(
                        *absolute.relative_to(system_alias).parts
                    )
                break
        return absolute

    def _relative_output_path(self, path, allowed_directories=None):
        absolute = self.normalize_path(path)
        try:
            relative = absolute.relative_to(self.output)
        except ValueError as error:
            raise ValueError("pixel output escapes identity token") from error
        if len(relative.parts) != 2 or relative.parts[0] not in self.DIRECTORIES:
            raise ValueError("pixel output path shape is invalid")
        if allowed_directories is not None and relative.parts[0] not in allowed_directories:
            raise ValueError("pixel output directory is invalid for this operation")
        return absolute, relative.parts[0], relative.parts[1]

    def normalize_output_path(self, path, allowed_directories=None):
        absolute, _, _ = self._relative_output_path(path, allowed_directories)
        return absolute

    def contains_output_path(self, path):
        absolute = self.normalize_path(path)
        try:
            absolute.relative_to(self.output)
        except ValueError:
            return False
        self._relative_output_path(path)
        return True

    def read_output_file(self, path, max_bytes):
        _, directory, leaf = self._relative_output_path(path)
        return _safe_read_from(self.descriptors[directory], leaf, max_bytes)

    def open_output_target(self, path):
        absolute, directory, leaf = self._relative_output_path(path, {"diff"})
        directory_fd = os.dup(self.descriptors[directory])
        try:
            try:
                os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError(f"output path already exists: {absolute}")
            return OutputTarget(directory_fd, leaf, absolute)
        except BaseException:
            os.close(directory_fd)
            raise

    def verify_output_payload(self, path, expected_payload):
        observed = self.read_output_file(path, len(expected_payload))
        if observed != expected_payload:
            raise ValueError("pixel output anchored payload readback mismatch")

    def validate_anchored(self):
        for name, descriptor in self.descriptors.items():
            if _identity_pair(descriptor) != self.token["identities"][name]:
                raise ValueError("output anchored identity changed")

    def validate_visible(self):
        visible = {}
        try:
            root_fd = _secure_directory(self.repo, self.output, False)
            visible["root"] = root_fd
            if _identity_pair(root_fd) != self.token["identities"]["root"]:
                raise ValueError("output visible root identity mismatch")
            for directory in self.DIRECTORIES:
                descriptor = _open_child_directory(root_fd, directory)
                visible[directory] = descriptor
                if _identity_pair(descriptor) != self.token["identities"][directory]:
                    raise ValueError("output visible subdirectory identity mismatch")
            self.validate_anchored()
        finally:
            for descriptor in visible.values():
                os.close(descriptor)


def secure_write(repo_root, identity_token, relative_path, encoding, stream):
    token = _decode_identity_token(identity_token)
    repo = _reject_symlink_components(repo_root)
    if str(repo) != token["repo_root"]:
        raise ValueError("output identity repo mismatch")
    relative = Path(relative_path)
    if relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] not in {
        "generated",
        "diff",
        "e2e",
    }:
        raise ValueError("unsafe secure writer relative path")
    output = repo / token["output_root"]
    root_fd = _secure_directory(repo, output, False)
    directory_fd = None
    try:
        if _identity_pair(root_fd) != token["identities"]["root"]:
            raise ValueError("output root identity mismatch")
        directory_fd = _secure_directory(repo, output / relative.parts[0], False)
        if _identity_pair(directory_fd) != token["identities"][relative.parts[0]]:
            raise ValueError("output subdirectory identity mismatch")
        payload = stream.read(DEFAULT_MAX_FILE_BYTES + 1)
        if len(payload) > DEFAULT_MAX_FILE_BYTES:
            raise ValueError("secure writer input budget exceeded")
        if encoding == "base64":
            try:
                payload = binascii.a2b_base64(payload, strict_mode=True)
            except binascii.Error as error:
                raise ValueError("invalid base64 writer input") from error
        elif encoding != "raw":
            raise ValueError("unsupported secure writer encoding")
        target = OutputTarget(os.dup(directory_fd), relative.parts[1], output / relative)
        try:
            try:
                details = os.stat(
                    target.leaf,
                    dir_fd=target.directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(details.st_mode):
                    raise ValueError("secure writer target is not regular")
            _publish_single(target, payload, "browser-writer")
        finally:
            target.close()
        requested_root = _secure_directory(repo, output, False)
        requested_subdir = None
        try:
            requested_subdir = _secure_directory(repo, output / relative.parts[0], False)
            if _identity_pair(requested_root) != token["identities"]["root"] or _identity_pair(
                requested_subdir
            ) != token["identities"][relative.parts[0]]:
                raise ValueError("output identity changed during write")
        finally:
            os.close(requested_root)
            if requested_subdir is not None:
                os.close(requested_subdir)
    finally:
        os.close(root_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def validate_output_identity(repo_root, identity_token, paths, keep_open=False):
    transaction = OutputIdentityTransaction(repo_root, identity_token)
    try:
        for path in paths:
            transaction.normalize_output_path(path, {"diff"})
        if keep_open:
            return transaction
    except BaseException:
        transaction.close()
        raise
    transaction.close()
    return None


def _portable_json_value(value, repo_root, ephemeral_root):
    if isinstance(value, dict):
        return {
            key: _portable_json_value(item, repo_root, ephemeral_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_portable_json_value(item, repo_root, ephemeral_root) for item in value]
    if not isinstance(value, str):
        return value
    prefix = "file://"
    raw = value[len(prefix) :] if value.startswith(prefix) else value
    candidate = Path(raw)
    if not candidate.is_absolute():
        return value
    candidate = Path(os.path.abspath(candidate))
    for label, root_path in (("repo", repo_root), ("ephemeral", ephemeral_root)):
        if root_path is None:
            continue
        normalized_root = Path(os.path.abspath(root_path))
        try:
            relative = candidate.relative_to(normalized_root)
        except ValueError:
            continue
        return f"{label}/{relative.as_posix()}"
    return f"external/{candidate.name}"


def _publish_single(target, payload, label):
    temporary = _stage_bytes(target, payload, label)
    try:
        os.rename(
            temporary,
            target.leaf,
            src_dir_fd=target.directory_fd,
            dst_dir_fd=target.directory_fd,
        )
        temporary = None
        os.fsync(target.directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=target.directory_fd)
            except FileNotFoundError:
                pass


def _replace_target(repo_root, path):
    repo, absolute, relative = _relative_under(repo_root, path)
    parent = repo.joinpath(*relative.parts[:-1])
    directory_fd = _secure_directory(repo, parent, True)
    leaf = relative.parts[-1]
    try:
        try:
            details = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(details.st_mode):
                raise ValueError(f"publish target is not a regular file: {absolute}")
        return OutputTarget(directory_fd, leaf, absolute)
    except BaseException:
        os.close(directory_fd)
        raise


def sanitize_json(input_path, output_path, repo_root, ephemeral_root):
    value = json.loads(_input_path(input_path, Budgets(
        DEFAULT_MAX_FILE_BYTES,
        DEFAULT_MAX_WIDTH,
        DEFAULT_MAX_HEIGHT,
        DEFAULT_MAX_PIXELS,
        DEFAULT_MAX_IDAT_BYTES,
        DEFAULT_MAX_DECOMPRESSED_BYTES,
        DEFAULT_MAX_CHANGED_PIXELS,
        DEFAULT_MAX_CLUSTER_PIXELS,
    )).read_text(encoding="utf-8"))
    portable = _portable_json_value(value, repo_root, ephemeral_root)
    payload = (json.dumps(portable, indent=2) + "\n").encode("utf-8")
    if output_path == "-":
        sys.stdout.buffer.write(payload)
        return
    target = _replace_target(repo_root, output_path)
    try:
        _publish_single(target, payload, "sanitize")
    finally:
        target.close()


def _read_visible_regular_at(directory_fd, leaf, max_bytes=DEFAULT_MAX_FILE_BYTES):
    try:
        visible_before = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError(f"evidence file is missing: {leaf}") from error
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(leaf, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(visible_before.st_mode) or not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"evidence source is not regular: {leaf}")
        visible_identity = (visible_before.st_dev, visible_before.st_ino)
        opened_identity = (opened.st_dev, opened.st_ino)
        if visible_identity != opened_identity:
            raise ValueError(f"evidence visible identity changed before read: {leaf}")
        if opened.st_size > max_bytes:
            raise ValueError(f"evidence file budget exceeded: {leaf}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"evidence file budget exceeded: {leaf}")
        payload = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        visible_after = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(visible_after.st_mode) or not stat.S_ISREG(opened_after.st_mode):
            raise ValueError(f"evidence source changed type during read: {leaf}")
        if (
            (opened_after.st_dev, opened_after.st_ino) != opened_identity
            or (visible_after.st_dev, visible_after.st_ino) != opened_identity
            or opened_after.st_size != len(payload)
            or visible_after.st_size != len(payload)
        ):
            raise ValueError(f"evidence visible identity changed during read: {leaf}")
        return {
            "payload": payload,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "identity": [opened_after.st_dev, opened_after.st_ino],
            "size": len(payload),
        }
    finally:
        os.close(descriptor)


def _safe_read_from(directory_fd, leaf, max_bytes=DEFAULT_MAX_FILE_BYTES):
    return _read_visible_regular_at(directory_fd, leaf, max_bytes)["payload"]


def publish_evidence(repo_root, run_root, publish_root):
    repo, run, _ = _relative_under(repo_root, run_root)
    _, publish, _ = _relative_under(repo, publish_root)
    if run == publish or run in publish.parents or publish in run.parents:
        raise ValueError("run and publish roots overlap")
    payloads = {}
    run_fds = {}
    publish_fds = {}
    requested_identities = {}
    try:
        for directory in ("generated", "diff", "e2e"):
            descriptor = _secure_directory(repo, run / directory, False)
            run_fds[directory] = descriptor
            for leaf in os.listdir(descriptor):
                relative = f"{directory}/{leaf}"
                payloads[relative] = _safe_read_from(descriptor, leaf)
        source_descriptor = _secure_directory(repo, publish / "source", False)
        publish_fds["source"] = source_descriptor
        for leaf in os.listdir(source_descriptor):
            relative = f"source/{leaf}"
            payloads[relative] = _safe_read_from(source_descriptor, leaf)
        publish_root_fd = _secure_directory(repo, publish, False)
        publish_fds["root"] = publish_root_fd
        requested_identities["root"] = _identity_pair(publish_root_fd)
        for directory in ("generated", "diff", "e2e"):
            descriptor = _secure_directory(repo, publish / directory, False)
            publish_fds[directory] = descriptor
        for directory in ("source", "generated", "diff", "e2e"):
            requested_identities[directory] = _identity_pair(publish_fds[directory])

        if set(payloads) != EVIDENCE_EXACT_SET:
            raise ValueError("evidence exact-set budget rejected")
        for directory in ("generated", "diff", "e2e", "source"):
            existing = set(os.listdir(publish_fds[directory]))
            expected = {
                relative.split("/", 1)[1]
                for relative in EVIDENCE_EXACT_SET
                if relative.startswith(f"{directory}/")
            }
            if existing != expected:
                raise ValueError(f"publish exact-set drift in {directory}")

        published_readbacks = {}
        for index, relative in enumerate(sorted(EVIDENCE_EXACT_SET)):
            directory, leaf = relative.split("/", 1)
            target = OutputTarget(
                os.dup(publish_fds[directory]),
                leaf,
                publish / relative,
            )
            try:
                _publish_single(target, payloads[relative], f"evidence-{index}")
            finally:
                target.close()
            _after_publish_file_hook(relative)
            readback = _read_visible_regular_at(publish_fds[directory], leaf)
            expected_payload = payloads[relative]
            if (
                readback["payload"] != expected_payload
                or readback["sha256"] != hashlib.sha256(expected_payload).hexdigest()
            ):
                raise ValueError(f"published payload content readback mismatch: {relative}")
            published_readbacks[relative] = readback

        for name, expected in requested_identities.items():
            requested = _secure_directory(
                repo,
                publish if name == "root" else publish / name,
                False,
            )
            try:
                if _identity_pair(requested) != expected or _identity_pair(
                    publish_fds[name]
                ) != expected:
                    raise ValueError("publish split-brain identity mismatch")
            finally:
                os.close(requested)

        checksum = "".join(
            f"{published_readbacks[relative]['sha256']}  {relative}\n"
            for relative in sorted(EVIDENCE_EXACT_SET)
        ).encode("utf-8")
        checksum_target = OutputTarget(
            os.dup(publish_fds["root"]),
            "SHA256SUMS.txt",
            publish / "SHA256SUMS.txt",
        )
        try:
            _publish_single(checksum_target, checksum, "checksums")
        finally:
            checksum_target.close()
        checksum_readback = _read_visible_regular_at(
            publish_fds["root"], "SHA256SUMS.txt"
        )
        if checksum_readback["payload"] != checksum:
            raise ValueError("published checksum content readback mismatch")
        for relative, initial_readback in published_readbacks.items():
            directory, leaf = relative.split("/", 1)
            final_readback = _read_visible_regular_at(publish_fds[directory], leaf)
            if (
                final_readback["payload"] != initial_readback["payload"]
                or final_readback["sha256"] != initial_readback["sha256"]
                or final_readback["identity"] != initial_readback["identity"]
                or final_readback["size"] != initial_readback["size"]
            ):
                raise ValueError(f"published payload changed after checksum: {relative}")
        for directory in ("source", "generated", "diff", "e2e"):
            final_entries = set(os.listdir(publish_fds[directory]))
            expected_entries = {
                relative.split("/", 1)[1]
                for relative in EVIDENCE_EXACT_SET
                if relative.startswith(f"{directory}/")
            }
            if final_entries != expected_entries:
                raise ValueError(f"publish final exact-set drift in {directory}")
        checksum_final = _read_visible_regular_at(
            publish_fds["root"], "SHA256SUMS.txt"
        )
        if (
            checksum_final["payload"] != checksum_readback["payload"]
            or checksum_final["sha256"] != checksum_readback["sha256"]
            or checksum_final["identity"] != checksum_readback["identity"]
        ):
            raise ValueError("published checksum changed before success")
        for name, expected in requested_identities.items():
            requested = _secure_directory(
                repo,
                publish if name == "root" else publish / name,
                False,
            )
            try:
                if _identity_pair(requested) != expected or _identity_pair(
                    publish_fds[name]
                ) != expected:
                    raise ValueError("publish identity changed before success")
            finally:
                os.close(requested)
    finally:
        for descriptor in list(run_fds.values()) + list(publish_fds.values()):
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description="Compare two 8-bit RGB/RGBA PNG files")
    parser.add_argument("--prepare-roots", action="store_true")
    parser.add_argument("--sanitize-json", action="store_true")
    parser.add_argument("--publish-evidence", action="store_true")
    parser.add_argument("--secure-write", action="store_true")
    parser.add_argument("--repo-root")
    parser.add_argument("--output-root")
    parser.add_argument("--publish-root")
    parser.add_argument("--run-root")
    parser.add_argument("--input-json")
    parser.add_argument("--output-json")
    parser.add_argument("--ephemeral-root")
    parser.add_argument("--identity-token")
    parser.add_argument("--output-identity-token")
    parser.add_argument("--relative-path")
    parser.add_argument("--encoding", choices=("base64", "raw"))
    parser.add_argument("--baseline")
    parser.add_argument("--candidate")
    parser.add_argument("--diff")
    parser.add_argument("--metrics")
    parser.add_argument("--max-diff-ratio", type=float)
    parser.add_argument("--max-mae", type=float)
    parser.add_argument("--per-channel-threshold", type=int, default=8)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-width", type=int, default=DEFAULT_MAX_WIDTH)
    parser.add_argument("--max-height", type=int, default=DEFAULT_MAX_HEIGHT)
    parser.add_argument("--max-pixels", type=int, default=DEFAULT_MAX_PIXELS)
    parser.add_argument("--max-idat-bytes", type=int, default=DEFAULT_MAX_IDAT_BYTES)
    parser.add_argument(
        "--max-decompressed-bytes", type=int, default=DEFAULT_MAX_DECOMPRESSED_BYTES
    )
    parser.add_argument(
        "--max-changed-pixels", type=int, default=DEFAULT_MAX_CHANGED_PIXELS
    )
    parser.add_argument(
        "--max-cluster-pixels", type=int, default=DEFAULT_MAX_CLUSTER_PIXELS
    )
    arguments = parser.parse_args()
    helper_modes = sum(
        int(value)
        for value in (
            arguments.prepare_roots,
            arguments.sanitize_json,
            arguments.publish_evidence,
            arguments.secure_write,
        )
    )
    if helper_modes > 1:
        parser.error("helper modes are mutually exclusive")
    try:
        if arguments.prepare_roots:
            if not all((arguments.repo_root, arguments.output_root, arguments.publish_root)):
                parser.error("--prepare-roots requires repo/output/publish roots")
            prepare_roots(
                arguments.repo_root,
                arguments.output_root,
                arguments.publish_root,
            )
            return 0
        if arguments.sanitize_json:
            if not all(
                (
                    arguments.repo_root,
                    arguments.input_json,
                    arguments.output_json,
                    arguments.ephemeral_root,
                )
            ):
                parser.error("--sanitize-json requires repo/input/output/ephemeral roots")
            sanitize_json(
                arguments.input_json,
                arguments.output_json,
                arguments.repo_root,
                arguments.ephemeral_root,
            )
            return 0
        if arguments.publish_evidence:
            if not all((arguments.repo_root, arguments.run_root, arguments.publish_root)):
                parser.error("--publish-evidence requires repo/run/publish roots")
            publish_evidence(
                arguments.repo_root,
                arguments.run_root,
                arguments.publish_root,
            )
            return 0
        if arguments.secure_write:
            if not all(
                (
                    arguments.repo_root,
                    arguments.identity_token,
                    arguments.relative_path,
                    arguments.encoding,
                )
            ):
                parser.error("--secure-write requires repo/token/path/encoding")
            secure_write(
                arguments.repo_root,
                arguments.identity_token,
                arguments.relative_path,
                arguments.encoding,
                sys.stdin.buffer,
            )
            return 0
    except (OSError, ValueError, zlib.error) as error:
        print(f"pixel_diff: {error}", file=sys.stderr)
        return 2

    required = {
        "--baseline": arguments.baseline,
        "--candidate": arguments.candidate,
        "--diff": arguments.diff,
        "--metrics": arguments.metrics,
        "--max-diff-ratio": arguments.max_diff_ratio,
        "--max-mae": arguments.max_mae,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error(f"missing required arguments: {', '.join(missing)}")
    if not 0 <= arguments.per_channel_threshold <= 255:
        parser.error("--per-channel-threshold must be between 0 and 255")
    if not math.isfinite(arguments.max_diff_ratio) or not 0 <= arguments.max_diff_ratio <= 1:
        parser.error("--max-diff-ratio threshold must be finite and between 0 and 1")
    if not math.isfinite(arguments.max_mae) or not 0 <= arguments.max_mae <= 255:
        parser.error("--max-mae threshold must be finite and between 0 and 255")
    budget_values = [
        arguments.max_file_bytes,
        arguments.max_width,
        arguments.max_height,
        arguments.max_pixels,
        arguments.max_idat_bytes,
        arguments.max_decompressed_bytes,
        arguments.max_changed_pixels,
        arguments.max_cluster_pixels,
    ]
    if any(value <= 0 for value in budget_values):
        parser.error("budgets must be positive")
    budget = Budgets(*budget_values)
    identity_transaction = None
    try:
        if arguments.output_identity_token:
            if not arguments.repo_root:
                parser.error("--output-identity-token requires --repo-root")
            identity_transaction = validate_output_identity(
                arguments.repo_root,
                arguments.output_identity_token,
                (arguments.diff, arguments.metrics),
                keep_open=True,
            )
        passed = compare(
            arguments.baseline,
            arguments.candidate,
            arguments.diff,
            arguments.metrics,
            arguments.per_channel_threshold,
            arguments.max_diff_ratio,
            arguments.max_mae,
            budget,
            identity_transaction=identity_transaction,
        )
        if identity_transaction is not None:
            identity_transaction.validate_visible()
    except (OSError, ValueError, zlib.error) as error:
        print(f"pixel_diff: {error}", file=sys.stderr)
        return 2
    finally:
        if identity_transaction is not None:
            identity_transaction.close()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
