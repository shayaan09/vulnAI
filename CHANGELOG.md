# Changelog

All notable to-dos for this project will be documented in this file.

---

## [Unreleased]

### TODO

[DONE] = Activity Completed

---

[] The current system for visit_Assign strips down records. in an obj.x = y assignment, it is stripping .x, and only stores obj currently since the func recurses down to the base variable. Change this function to not strip data like this. Using maybe a dict that stores the targets

[] visit_Assign is currentl;y storing alot of raw nodes. they will be useless for the analyzer. store their values, or their class names at the least

[] recursiveStmtBuild() currently treats each if statement in a nested if case as its own self contained block. SO, an extra inner join block is created every time the nesting goes deeper. This is fine, but i'd rather not keep it since it in large programs it'll create ALOT of them. 