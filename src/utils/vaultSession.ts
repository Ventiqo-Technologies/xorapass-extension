/** Worker-local generations cancel work even across lock -> unlock of one account. */
export class VaultSession {
  private generation = 0;
  private blocked = false;
  private writes: Promise<void> = Promise.resolve();

  capture(): number | null {
    return this.blocked ? null : this.generation;
  }

  isCurrent(generation: number): boolean {
    return !this.blocked && generation === this.generation;
  }

  /** Synchronous: deny pending and new requests before any cleanup awaits. */
  invalidate(): number {
    this.blocked = true;
    return ++this.generation;
  }

  /** Serialize replacement/clear writes so an older write cannot win last. */
  commit(generation: number, write: () => Promise<void>, unlocked: boolean): Promise<boolean> {
    const result = this.writes.then(async () => {
      if (generation !== this.generation) return false;
      await write();
      if (generation !== this.generation) return false;
      this.blocked = !unlocked;
      return true;
    });
    this.writes = result.then(() => undefined, () => undefined);
    return result;
  }
}
