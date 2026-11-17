---
version: 1
slug: "crates-ui-src"
primary_target: "crates/ui/src"
related_targets: []
---

MODE: operate
DIRECTION: Transit wayfinding (picked by the user; switches for on/off borrowed from the road-atlas sketch).

THESIS: The app is a station concourse for the machine's traffic: a dark rail of places on the left, one signal colour (#ffcc00) for what waits for the user and where they are, and plain, dense, readable data everywhere else.
OWN-WORLD: Signage, not dashboards. Ink #16191d rail in both modes; signal yellow only for waiting prompts, counts, the current place and selection; allow green and deny red as small square marks with a word; Overpass for the interface (Highway Gothic lineage), Overpass Mono for paths, hosts, ports, times and byte counts.
STORY: A prompt arrives → a yellow sign appears above whatever page is open → one click goes to the prompt card, whose header is the same sign → choose the rule, the duration, answer. Otherwise the user scans Events, edits Rules, and nothing they arranged (column widths) moves.
FIRST VIEWPORT: Rail with node name and mode; page title strip; the page's toolbar (wraps, never clips); a table whose clipped values read in full on hover.
FORM: seed:ec968c05198aef82. Flat surfaces, 1px borders, radius 5 (8 for cards), no shadows; 30px rail rows in four groups (decide, watch, control, node); 44px title strip; tables flush to the edges.
FINISH: Every page readable at 1280x720 in light and dark, no clipped toolbar, no unreadable truncation, the signal colour never used for decoration.
