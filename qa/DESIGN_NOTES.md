# Design notes (10 November 2026, second pass)

## Concept

A scholar's instrument with the finish of a well-made object. The product sits in the rayvelabs.com family (warm paper, ink, hairline rules, one gold accent, serif display type, mono labels) and takes its neutrals from brushed metal: silver and graphite. Almost nothing is colored; gold appears as a rule, a numeral, one italic line of a headline and the light on the art. The signature is an original generative drawing, the "threat print": contour ridges in the shape of a fingerprint, silver with gold catching the light, computed in `ui.print_art` with no image file.

The second pass answered an outside audit that said: the hero and the sign-in screen were strong, and under them the site was a grid of white cards with one drawing used about ten times. What changed is listed under "Second pass".

## Tokens

| Token | Value | Use |
|---|---|---|
| paper | `#fbfbf9` | page ground (rayvelabs.com `--bg`) |
| deep paper | `#f4efe3` | callouts, the band after the five steps, the study row of the gains chart |
| veil | `#fdfcf7` | table heads, notices, the run log, the menu |
| card | `#ffffff` | data cards (organization panels, hypothesis tiles, stage cards, sample cards) |
| silver | `#f5f5f7`, `#e8e8ed` | light buttons on graphite, chips |
| ink (graphite) | `#1d1d1f` | text, primary buttons, the top rule of editorial columns, centralized training |
| ink 2 | `#424245` | body text |
| muted | `#6e6e73` | secondary text (the lightest gray used for small text) |
| rules | `#e3e0d8`, `#eeebe4` | hairlines |
| gold | `#9d8552` | rules, marks, large numerals, sanitized attack-record sharing |
| bright gold | `#c4a565` | gold on graphite |
| gold ink | `#7a6537` | small gold text (labels, eyebrows, units) |
| steel | `#44608a` | federated learning |
| silver bar | `#b4b7bf` with edge `#7f828a` | isolated training |
| copper, hatched | `#a8623f` | the experimental arm (always hatched) |
| ok, warn, no | `#2f6b4f`, `#8a5a1c`, `#8c2f2a` | verdict marks, notices, the 5-point rule line |
| black | `#0b0b0c` to `#2b2b30` | the graphite stage: hero, sign-in panel, the plate of the four training conditions |

Type: Source Serif 4 (display, numerals, quotations), Inter (interface and body), JetBrains Mono (small upper-case labels, the run log). All three are served from `static/` under the SIL Open Font License. No page calls a third-party server.

## Second pass: what changed

**The print is now a family.** `ui.print_art` draws four pattern families, as on a real hand: whorl, loop, arch and double loop. A seed picks the family, the lean, which ridges are gold and where the ridges break; the same seed always gives the same drawing. `ui.art_seed(name)` and `ui.art_kind(name)` turn any name into a seed and a family, so every inner page has its own print (two pages per family), every sample file has its own small print on its card, every scorecard carries the print of its dataset, and section heads on Results, Agent, Research and Organizations carry a quiet partial print. The hero keeps the original whorl.

**Overview, below the hero, is a sequence of set pieces instead of card grids.**
- The five steps are one line with five stations and five large gold numerals. The line draws from left to right as the section scrolls into view; at 1100 px and below it turns into a vertical line down the left.
- The four training conditions are one scene on a graphite plate with its own print: A, B and C in four panels, with what travels under each condition (nothing, gold squares for records, steel dots for model weights, squares into "one place"). Pointing at one condition dims the other three.
- The decision rule is three marks under ink hairlines: a large 5 (points), a large 1 (point), and a print with the word trade-off.
- The three ways in are three ruled columns, each with its own link directly under its text.
- The limits are quiet two-column prose under a hairline.
- The band after the steps is a deep-paper plate, so graphite is kept for the hero and the conditions.

**Inner pages lost the card grid where the content is prose.**
- Organizations: ruled columns ("Who it is for"), numbered rows in two columns ("What you get"), three ruled options each with its own link, two ruled lists for built and designed.
- Agent: three numbered columns, two ruled columns for what a fingerprint holds and does not.
- Students: six numbered rows with the time for each at the right.
- Glossary: terms and definitions in two ruled columns, the way a glossary is set in a book.
- Results: the two gains charts are figures with a legend and a labelled caption ("Figure 1", "Figure 2"), with no box around them; names in the chart have room for 50 characters.
- Scorecards: bars are now real text and rules (HTML, not a scaled drawing), so labels are 13 px on every screen; the verdict rows wrap instead of squeezing their labels; drawers are ruled rows, not boxes.
- Cards remain where they hold data: organization panels, hypothesis tiles, stage cards, sample cards.

**Live demo.** Each sample is one card with its own print and its own button. After a run the page is 9,148 px tall at 1440 px (it was 11,497): finished stages keep their head, the "What just happened" line and the one thing that tells the story (the role table, the removed columns, the three organizations, what travelled), and the long lists are one click away in ruled drawers. The stage rail is slimmer, made of glass, and stays under the navigation bar while the stages scroll. The four training conditions in stage 5 are one quiet strip. The run log is set as a log (mono, small).

**Phone (390 px).**
- Sign-in: the form comes before the art.
- Navigation: the row of links becomes a "Menu" button (Streamlit's own popover, no script) that lists all nine pages with 46 px rows and marks the current one with a gold dot. The switch happens at 820 px.
- Every card or text that has a button keeps that button directly under it when rows stack (sample cards, the ways in, the deployment options).
- Wide tables and the gains charts scroll sideways inside their own holder, with a fade at the right edge.
- Buttons, links, tabs, drawers, radios and checkboxes are at least 44 px tall.

**States that had no image were styled and now have one:** Evaluate with a file loaded (selects, the removed-columns list, radio, checkbox, run button), Evaluate while running (the status box as a log), Evaluate after a run, the Sanitize tab with a file, the Agent page with the example fingerprint, the sign-in screen after a wrong password, the phone menu open. Notices (info, warning, error, success) are paper with a colored rule at the left.

## What moves, and how

Everything is CSS on inline SVG and HTML; there is no script and no iframe.

- The print draws itself ring by ring from its core, then a band of gold light crosses it. The band now crosses three times and rests; pointing at the print sends it across again.
- The hero text rises into place; the gold italic line carries a slow sheen, twice; the glass card arrives and its bars grow.
- Scroll-linked (`animation-timeline: view()`, inside `@supports`; a browser without it shows everything in place): the line of the five steps draws, the stations and numerals rise one after another, the plate and its four panels rise, the numerals of the decision rule settle out of a blur, rows, figures and glossary entries rise, bars grow, and the hero print and the plate print drift a little against the page for depth.
- In the conditions scene, marks travel between A, B and C. These loop; they are the explanation, and they are away from the numbers.
- The stage rail of the Live demo fills with gold as each stage completes; the new check mark pops; the running stage breathes.
- Pointer: cards lift, a sample's print turns and grows a little, the hairline over a way in turns gold, one condition comes forward.
- `prefers-reduced-motion: reduce` turns all of it off and shows still marks in the diagrams.

Checked in a real browser (headless Chromium): `screenshots/design/motion_overview_and_live_demo.webm` and ten frames `motion_frame_1` to `motion_frame_10` beside it. Measured in that run: the step line is at 0.42 of its length while the section enters and at full length once it is in view. On the Evaluate page, no time-based animation was running after a widget caused a rerun, so entrances do not replay on a rerun.

## Verified on the final files

- Tests: 82 pass (33 app, 49 pressure).
- Praxis checker (`--advisor`) on rendered text, outputs stored in `qa/checker_runs/` and regenerated after the last page change: 41 files, 0 errors (eight pages, 25 scorecards with the chart hover text, the Live demo after a run, the Agent page with the example fingerprint, the sign-in screen, two reports, the text of the card files).
- Browser parts of the pressure suite on the final pages: sign-in path 7 of 7; hostile fingerprints through the page, none failed; hostile uploads through the page 4 of 4 (and 4 of 4 with the patched copy); five browser sessions at once, 6 checks passed. `qa/PRESSURE_TEST_REPORT.md` rebuilt: 0 failed, 0 open.
- Screenshots, `screenshots/design/final/` (59 images): all nine pages at 1440, 1280, 1024 and 390 px; and the states named above at 1440 and 390 px (the phone menu at 390 only; the two "while running" and the two "rail in view" images are one screen each). `screenshots/layout/`: the five images regenerated under the same names.
- Brand switch: with `TP_BRAND=Aurelia` the old name appears on none of the nine pages (counted in the page text); the agent's real file name `threatprint_agent.py` stays on the Agent page. `screenshots/design/brand_switch_TP_BRAND_Aurelia.png`.
- Contrast (WCAG 2.1 ratio), unchanged tokens: ink on paper 16.2; body on paper 9.7; muted on paper 4.9; gold-ink labels on paper 5.4; hero text on graphite 15.2. New in this pass: text on the conditions plate 7.6 (5.5 in its lightest corner), its small index label 5.1, its heading 12.9, its gold label 6.0; the run log 9.7; notice text 9.0 to 9.3; menu links 16.4; band text on deep paper 8.7; navigation text on the glass bar over graphite 6.8. The large gold numerals are decoration (hidden from screen readers); the step and row titles beside them carry the meaning.

## Still short of his words, ranked

1. Nobody has looked at this in Safari or Chrome on his Mac. Every image was made in headless Chromium on Linux, and the scroll-linked motion needs a current Chromium or Safari; elsewhere the page is still.
2. Streamlit draws the page: a cold load shows about a second of its own gray skeleton before the design appears.
3. The long pages are still long. The Live demo after a run is 9,148 px on a desktop and 17,729 px on a phone, because the whole scorecard sits in stage 6; Results is about 8,000 px because it holds two 25-row figures.
4. The gains charts are exact and dense. On a phone they scroll sideways; they do not turn into a chart made for a phone.
5. The pointer gets an answer only on hover (lift, light, focus). There is no tilt or true depth; depth is glass, shadow and a small scroll drift.
6. The marks in the conditions scene loop for as long as the scene is on screen.
7. Native widgets are restyled, not redrawn: the uploader keeps Streamlit's own line of text, the select list and the phone menu open as Streamlit's popovers.
8. The report uses the reader's own serif, because it is one self-contained file with no font inside.
9. On a direct page address the browser console shows two "404" lines from Streamlit's own start-up probing. They were there before this pass and nothing on the page is missing.
