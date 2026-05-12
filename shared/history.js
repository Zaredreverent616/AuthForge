/**
 * AuthForge — Undo history (shared/history.js)
 *
 * Keeps a bounded log of reversible actions and exposes undo()/redo().
 *
 * Each entry is `{ description, undo: async () => {}, redo: async () => {}, at }`.
 * The store lives in memory only — by design, closing the popup discards
 * the history (otherwise stale undos against a long-gone session token
 * would be a worse user experience than no undo at all).
 */

export class HistoryStore {
  constructor(limit = 50) {
    this.limit = limit;
    this.undoStack = [];
    this.redoStack = [];
    this.listeners = new Set();
  }

  /** Subscribe to history changes. Returns an unsubscribe function. */
  onChange(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  _emit() {
    for (const fn of this.listeners) fn(this);
  }

  /**
   * Record a new action AND execute it. The redo callback is invoked
   * immediately; that means the caller writes the action description and
   * undo/redo logic in one place, and the bookkeeping is automatic.
   */
  async push({ description, undo, redo }) {
    await redo();
    this.undoStack.push({ description, undo, redo, at: Date.now() });
    if (this.undoStack.length > this.limit) this.undoStack.shift();
    // Any new action invalidates the redo branch — that's the standard
    // editor convention; trying to merge branches is more confusing.
    this.redoStack = [];
    this._emit();
  }

  canUndo() {
    return this.undoStack.length > 0;
  }
  canRedo() {
    return this.redoStack.length > 0;
  }

  async undo() {
    const entry = this.undoStack.pop();
    if (!entry) return null;
    try {
      await entry.undo();
      this.redoStack.push(entry);
      this._emit();
      return entry;
    } catch (e) {
      // Restore the entry so the user can try again; surface the error.
      this.undoStack.push(entry);
      this._emit();
      throw e;
    }
  }

  async redo() {
    const entry = this.redoStack.pop();
    if (!entry) return null;
    try {
      await entry.redo();
      this.undoStack.push(entry);
      this._emit();
      return entry;
    } catch (e) {
      this.redoStack.push(entry);
      this._emit();
      throw e;
    }
  }

  clear() {
    this.undoStack = [];
    this.redoStack = [];
    this._emit();
  }

  /** Snapshot for UI display — newest-first. */
  list() {
    return [...this.undoStack].reverse().map((e, i) => ({
      index: i,
      description: e.description,
      at: e.at,
    }));
  }
}
