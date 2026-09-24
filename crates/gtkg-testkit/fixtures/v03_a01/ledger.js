import { Entry } from "./model.js";

export function emit(entry) {
  persist(entry);
}
