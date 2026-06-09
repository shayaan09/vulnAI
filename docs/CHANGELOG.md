# Changelog

All notable to-dos for this project will be documented in this file.

---

## [Unreleased]

### TODO

[X] = Activity Completed

---

[] The current system for visit_Assign strips down records. in an obj.x = y assignment, it is stripping .x, and only stores obj currently since the func recurses down to the base variable. Change this function to not strip data like this. Using maybe a dict that stores the targets

[] visit_Assign is currentl;y storing alot of raw nodes. they will be useless for the analyzer. store their values, or their class names at the least

[] recursiveStmtBuild() currently treats each if statement in a nested if case as its own self contained block. SO, an extra inner join block is created every time the nesting goes deeper. This is fine, but i'd rather not keep it since it in large programs it'll create ALOT of them. 

[X] ReachingDefAnalyzer and the UseDefAnalyzer classes only handle the Name node currently for barebones functionality to work. Other types of assignments and expressions need to be handled. 

[X] Improve use-def edge precision later. Current design stores useDefEdges as: statement -> set of reaching definitions. This is good enough for the first DFG, but later need to refine it to track either statement -> used variable -> reaching definitions, or exact AST Name use node → reaching definitions, to know precisely which variable/use each definition connects to.

[] Vulnerability sink + sanitizer + source lists are too broad. Will result in ALOT of false catches. Fix.

[X] In the TaintAnalyzer class, self.taintedDefs is global, need to make it per rule. an XSS sanitizer will NOT sanitize an SQLi source

[X] Test `InterproceduralTaintAnalyzer` with pytest, ensure the entire pipeline is running

[X] Changed Optional[] from typing to the union operator, however, this may struggle with older python enviornments, like below 3.10, add more version compatibility