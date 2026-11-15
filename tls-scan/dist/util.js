"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Semaphore = exports.sleep = void 0;
exports.mapPool = mapPool;
/** Run fn over items with at most `size` in flight. Order of results matches items. */
async function mapPool(items, size, fn) {
    const out = new Array(items.length);
    let next = 0;
    const workers = Array.from({ length: Math.max(1, Math.min(size, items.length)) }, async () => {
        for (;;) {
            const i = next++;
            if (i >= items.length)
                return;
            out[i] = await fn(items[i], i);
        }
    });
    await Promise.all(workers);
    return out;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
exports.sleep = sleep;
/** Counting semaphore used as a global cap on concurrent sockets. */
class Semaphore {
    constructor(permits) {
        this.permits = permits;
        this.queue = [];
    }
    async acquire() {
        if (this.permits > 0) {
            this.permits--;
            return;
        }
        await new Promise((resolve) => this.queue.push(resolve));
    }
    release() {
        const next = this.queue.shift();
        if (next)
            next();
        else
            this.permits++;
    }
}
exports.Semaphore = Semaphore;
