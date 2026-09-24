import {A2uiClientMessageSchema, MessageProcessor} from '@a2ui/web_core/v0_9';
import {A2uiSurface, basicCatalog} from '@a2ui/lit/v0_9';

void A2uiSurface;

const evidence = {
  ready: false,
  catalogId: basicCatalog.id,
  messageCount: 0,
  surfaceId: null,
  componentIds: [],
  indexCount: 0,
  initialTitle: null,
  initialBody: null,
  actions: [],
  actionSchemaValid: false,
  updatedTitle: null,
  updatedBody: null,
  errors: [],
};
globalThis.__GTKG_H05__ = evidence;
globalThis.__GTKG_XSS_SENTINEL__ = false;

function decodeHex(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error('missing or invalid stream hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

try {
  const streamText = decodeHex(globalThis.__GTKG_A2UI_STREAM_HEX__);
  const messages = streamText
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  evidence.messageCount = messages.length;

  let surface;
  const processor = new MessageProcessor([basicCatalog], undefined, {version: 'v0.9'});
  processor.onSurfaceCreated((created) => {
    if (created.id === 'gtkg-main') surface = created;
  });
  processor.processMessages(messages);
  surface ??= processor.model.getSurface('gtkg-main');
  if (!surface) throw new Error('MessageProcessor did not create gtkg-main');
  surface.onAction.subscribe((action) => {
    const wrapped = {version: 'v0.9', action};
    const parsed = A2uiClientMessageSchema.safeParse(wrapped);
    evidence.actionSchemaValid = parsed.success;
    evidence.actions.push(action);
    if (!parsed.success) evidence.errors.push(parsed.error.message);
  });

  const element = document.querySelector('#surface');
  element.surface = surface;
  await element.updateComplete;
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));

  evidence.surfaceId = surface.id;
  evidence.componentIds = [...surface.componentsModel.entries].map(([id]) => id).sort();
  evidence.indexCount = surface.dataModel.get('/index')?.length ?? 0;
  evidence.initialTitle = surface.dataModel.get('/document/title');
  evidence.initialBody = surface.dataModel.get('/document/body');
  globalThis.__GTKG_APPLY_DOCUMENT__ = async (title, body) => {
    processor.processMessages([
      {version: 'v0.9', updateDataModel: {surfaceId: 'gtkg-main', path: '/document/title', value: title}},
      {version: 'v0.9', updateDataModel: {surfaceId: 'gtkg-main', path: '/document/body', value: body}},
    ]);
    await element.updateComplete;
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    evidence.updatedTitle = surface.dataModel.get('/document/title');
    evidence.updatedBody = surface.dataModel.get('/document/body');
  };
  document.querySelector('#status').textContent = 'Official A2UI stream rendered';
  evidence.ready = true;
} catch (error) {
  evidence.errors.push(String(error?.stack ?? error));
  document.querySelector('#status').textContent = 'Renderer failed';
  throw error;
}
