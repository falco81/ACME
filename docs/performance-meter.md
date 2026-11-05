# The performance meter

How busy this node is - the processor, the memory, the disks and the network - in the header of the
administration pages, every 3 seconds while the page is shown. From ai 1.0.72-1.0.76, here since
acme 1.0.48.

**Off unless switched on**: **Settings → About → The performance meter in the header** (`perf_meter`,
`acme --set perf_meter=1`). Off, nothing is shown, the pages ask nothing, and nothing is read or
written for it on any node. On, every full administrator sees it - each choosing its look, or not
to see it, in **Your account → Performance meter**.

## What it shows

Four numbers in the header, in the look chosen:

| Look (`hload`) | |
|---|---|
| `graphs` - the default | with a graph of the last two minutes |
| `pills` | pills with a bar |
| `line` | one plain line |
| `rings` | with rings |
| `off` | nothing in the header (for this account) |

- **CPU** - busy over the last reading, every core together, and the load averages in its tip;
- **RAM** - in use without what the kernel keeps as cache and gives back (and the swap);
- **Disk** - read ↓ and written ↑, every whole disk together (no partitions, loop, RAM or device-mapper
  devices twice);
- **Net** - in ↓ and out ↑, every network card together (no loopback, no bridges of containers, a bond
  counted and not its members).

From 70 % the number is yellow, from 90 % red. Each number keeps its place, so nothing moves as it
changes. It sits on the row of the name and the state of the node, a cluster's nodes one under the
other there; when it would push the account's buttons off that row, it goes to a row of its own under
it, then on a narrower window the disks and the network leave it; on a phone it is not shown.

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
- The graphs are drawn on a line of time and move on smoothly between the readings (one SVG
  animation each, nothing redrawn by a timer), a few seconds behind: this node's readings come
  every 3 s, another node's every 5 s, so a new one is always added beyond the right edge and
  nothing jumps. Their scale follows the highest reading shown and goes back down slowly. Paused,
  they stand still; with *reduce motion* set in the system they step with each reading instead.
- The pages do not ask while they are hidden, nor while the live updates are paused.
- **In a cluster every node is shown**, a row of numbers each under its name, and each with its
  panel. Through the database, and only while a page watches: the node the page is on notes so in a
  row of its own (`load:watch:NODE`, at most every 15 s); every other node sees it in the query its
  daemon makes every 5 s anyway, and while watched writes its reading into its own row
  (`load:now:NODE`) every 5 s - its details only while a panel of it is open. A node not heard from
  lately is shown dimmed. Nobody watching - or the meter off - nothing is read or written.
- A page loaded again (F5), or opened beside another, goes on from the last two minutes read: the
  daemon keeps the readings it made because a page asked (`?hist=1` with the first one) - nothing
  is read for that.
- The choices are kept with the account (`prefs`: `hload`, `hpanel`), on every device it signs in from.

Code: `acmelib/engine/468_how_busy_the_server_is.py` (the daemon), `web/assets/hload.js` and
`hload.css` (the pages). Tests: `test/test_perfmeter.py`.
