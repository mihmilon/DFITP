<?php
$xml = simplexml_load_file('xml/index.xml');
$xml2 = simplexml_load_file('xml/test_8c.xml');

mkdir("files");
$f = fopen("files/funcStrtEnd.txt", "w");
$f2 = fopen("files/_codeExp.txt", "w");

$cntr=0;
foreach($xml->compound->member as $res):
	if($res['kind']=="function"){
		$funcId[$cntr] = $res['refid'];
		$funcName[$cntr] = $res->name;
		$cntr++;	
	}
endforeach;

$mainRootFuncName = "find_css_set";

//function call from main with start and end line
//echo "****function start end \n";
foreach($xml2->compounddef->sectiondef as $result):
		foreach($result->memberdef as $result2):
			$refid = $result2['id'];
			for($a=0;$a<$cntr;$a++){
				if($funcId[$a] == "$refid" && $funcName[$a] == $mainRootFuncName){
					$main = $result2->location;
					//echo "main"." ".$main['bodystart']." ".$main['bodyend'];
					fwrite($f,$mainRootFuncName." ".$main['bodystart']." ".$main['bodyend']."\n");
					$mainstart = $main['bodystart'];
					$mainend = $main['bodyend'];
					
					//echo "\n";
					foreach($result2->references as $result3):
						//echo $result3." ".$result3['startline']." ".$result3['endline']."\n";
						fwrite($f,$result3." ".$result3['startline']." ".$result3['endline']."\n");
					endforeach;
				}
			}
			
		endforeach;	
endforeach;
fclose($f);

//find from code line
//echo "****Function called from main\n";
foreach($xml2->compounddef->programlisting as $res):
	foreach($res->codeline as $res2):
		foreach($res2->highlight as $res3):
			foreach($res3->ref as $res4):
				$id = $res4['refid'];
				for($a=0;$a<$cntr;$a++){
					if($funcId[$a] == "$id" && $funcName[$a] != $mainRootFuncName ){
						if($res2['lineno'] >= "$mainstart" && $res2['lineno'] <= "$mainend"){
							//echo $res4." ".$res2['lineno']."\n";
							fwrite($f2,$res4." ".$res2['lineno']."\n");
							break;
						}
					}
				}
			endforeach;
		endforeach;
	endforeach;
endforeach;
fclose($f2);
//echo "\n\n";

//--------------------------------------------------------------------------------------------------

//echo "create extra node2node that should be added\n";


?>

