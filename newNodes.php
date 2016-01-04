<?php
$f3 = fopen("files/funcStrtEnd.txt", "r");
$f4 = fopen("files/_codeExp.txt", "r");
$f5 = fopen("files/node2node.txt", "a");

$counterf3=0;
while (!feof($f3) ) {
	fscanf($f3, "%s %d %d", $funcN[$counterf3], $nStart[$counterf3], $nEnd[$counterf3]);
	$counterf3++;
}
fclose($f3);

$counterf4=0;
while (!feof($f4) ) {
	fscanf($f4, "%s %d", $funcN2[$counterf4], $n2StartBody[$counterf4]);
	$counterf4++;
}

fclose($f4);


for($j=0;$j<$counterf4;$j++){
	//echo $funcN2[$j];
	for($k=0;$k<$counterf3;$k++){
		if($funcN2[$j] == $funcN[$k]){
			//echo $n2StartBody[$j]." ". $nStart[$k]."\n".$nEnd[$k]." ". ($n2StartBody[$j]+1)."\n";
			fwrite($f5,$n2StartBody[$j]." ". $nStart[$k]."\n".$nEnd[$k]." ". ($n2StartBody[$j]+1)."\n");
			break;
		}
	}
}
fclose($f5);

?>


