# vulnAI Rules Overview

This folder contains vulnerability rules used by vulnAI. Each rule tells the analyzer what dangerous pattern or data-flow path to look for.

The basic taint-flow idea is:

`source -> sink without sanitizer = possible vulnerability`

A source is where untrusted data enters the program.  
A sink is a dangerous operation.  
A sanitizer is a safety check or protection step.
