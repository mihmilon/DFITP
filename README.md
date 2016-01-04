# DFITP
Data flow based integration test paths


Source code -> xml
1.	Put source file in a folder.(Elevator.c in auto code)
2.	Using doxygen create xml file. Two xml file will be generated inside xml folder named index.xml and test.xml(test_8c).

Call graph generation
3.	Now use callGraph.php to generate call graph
a.	Php –f callGraphinfo.php
b.	Modify output files (_codeExp.txt, funcStrtEnd.txt if necessary)
c.	funcStrtEnd.txt should contain only caller,callee function.

Source code -> CFG
4.	Make CFG from source code compile CFG.exe file. It take start and end node of functions (funcStrEnd.txt) and source code as input.
5.	The output contain node2node representation.

Add new nodes in cfg
6.	Run newNodes.php for adding new nodes in node2node.txt.

CFG->paths
7.	Now generate path from control flow. Node2node will act as input here. Compile cfg_path.exe for it. Manual input root node and leave node.
8.	The output testpath.txt contain all paths from root to leave node.

Cscope 
9.	Using cscope find all occurrence of interacting variables and defined/used by variables.
10.	 Output is a text file contain all statement of the variables.

Final path
11.	Input: testpath.txt and validdu.txt. 
a.	Valid du contain 215 47 219 184, 215 47 219 187 these kind of DU pair/path. Which testpath have covered each du pair consider as final test path.

=====================================================================================================================================
Final output: 
Number of path initially generated = ...
Number of path generated after DU coverage = ...
Path reduction rate= ...%
=====================================================================================================================================
Input files:
Index.xml, test_8c.xml, validdu.txt
=====================================================================================================================================
