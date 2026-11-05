# The performance meter

How busy this node is - the processor, the memory, the disks and the network - in the header of the
administration pages, every 3 seconds while the page is shown. From ai 1.0.72-1.0.76, here since
acme 1.0.48.

**Off unless chosen.** Each full administrator switches it on for their own account: **Your account →
Performance meter** (the account button in the header). Nothing is read on the server while it is
off, and the pages ask nothing.

## What it shows

Four numbers in the header, in the look chosen:

| Look (`hload`) | |
|---|---|
| `off` - **the default** | nothing in the header |
| `graphs` | with a graph of the last two minutes |
| `pills` | pills with a bar |
| `line` | one plain line |
| `rings` | with rings |

- **CPU** - busy over the last reading, every core together, and the load averages in its tip;
- **RAM** - in use without what the kernel keeps as cache and gives back (and the swap);
- **Disk** - read ↓ and written ↑, every whole disk together (no partitions, loop, RAM or device-mapper
  devices twice);
- **Net** - in ↓ and out ↑, every network card together (no loopback, no bridges of containers, a bond
  counted and not its members).

From 70 % the number is yellow, from 90 % red. Each number keeps its place, so nothing moves as it
changes. On a narrower window the meter goes to a row of its own under the header, then the disks and
the network leave it; on a phone it is not shown.

Pointing at a number (tapping it on a tablet) opens its details, in the style chosen:

| Style (`hpanel`) | |
|---|---|
| `tiles` - the default | a card for each core |
| `table` | a row for each core, as htop |
| `map` | the cores as coloured squares, rings for the whole |
| `wide` | the processor, the memory, the disks and the network side by side |
| `off` | no details - only a short tip |

The details: each core (busy, MHz, temperature), the sensors, each disk (read, written, busy, its
temperature), the filesystems, each network card (state, speed, rates), and the processes taking the
most processor and memory. A virtual machine has no temperature sensors, and says so.

What plexmon 2.7.1-2.7.4 found, here too:

- the temperatures of NVMe disks, and of SATA disks with the `drivetemp` module loaded, are read
  as they are (acme's servers do not put their disks to sleep - plexmon, which does, skips drivetemp);
- free space only of the kernel's own filesystems (ext4, xfs, btrfs, zfs, ...) - never FUSE, a
  network share (a server away would hang every page's meter) nor FAT;
- each thread's temperature is its physical core's, by the CPU topology (hyperthreading, cores
  numbered with gaps, several packages);
- a bar or a ring is exactly its value - nothing at 0 % - and a process's bar is its share of one
  core, or of the memory in use.

## How it works

- `GET /api/load` (the pages: `?api=load`), **full administrators only** - what the server is doing and
  its processes are said. `?detail=1` adds the details, asked **only while a panel is open**.
- It reads `/proc` and `/sys` when asked; **nothing runs in the background**. Asks within the same
  second share one reading (ten pages open are one reading).
- The pages do not ask while they are hidden, nor while the live updates are paused.
- In a cluster, it is the node that answers the pages - the one holding the VIP address (its name is
  in the answer as `node`).
- A page loaded again (F5), or opened beside another, goes on from the last two minutes read: the
  daemon keeps the readings it made because a page asked (`?hist=1` with the first one) - nothing
  is read for that.
- The choices are kept with the account (`prefs`: `hload`, `hpanel`), on every device it signs in from.

Code: `acmelib/engine/468_how_busy_the_server_is.py` (the daemon), `web/assets/hload.js` and
`hload.css` (the pages). Tests: `test/test_perfmeter.py`.
