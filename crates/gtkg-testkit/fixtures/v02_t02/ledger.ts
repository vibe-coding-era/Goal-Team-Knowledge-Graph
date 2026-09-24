import { Entry } from "./model";

export function emit(entry: Entry) {
  persist(entry);
}
