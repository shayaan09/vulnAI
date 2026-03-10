# Changelog

All notable to-dos for this project will be documented in this file.

---

## [Unreleased]

### TODO

[DONE] = Activity Completed

---

[] The current system for visit_Assign strips down records. in an obj.x = y assignment, it is stripping .x, and only stores obj currently since the func recurses down to the base variable. Change this function to not strip data like this. Using maybe a dict that stores the targets