<?php

$domain = $_GET['domain'];
function QueryWhoisServer($whoisserver, $domain) {
	$port = 43;
	$timeout = 10;
	$fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout) or die("Socket Error " . $errno . " - " . $errstr);
	fputs($fp, $domain . "\r\n");
	$out = "";
	while(!feof($fp)){
		$out .= fgets($fp);
	}
	fclose($fp);
	$res = "";
	if((strpos(strtolower($out), "error") === FALSE) && (strpos(strtolower($out), "not allocated") === FALSE)) {
		$rows = explode("\n", $out);
		foreach($rows as $row) {
			$row = trim($row);
			if(($row != '') && ($row{0} != '#') && ($row{0} != '%')) {
				$res .= $row."\n";
			}
		}
	}
	return $res;
}
if($domain) {
	$domain = trim($domain);
	if(substr(strtolower($domain), 0, 7) == "http://") $domain = substr($domain, 7);
	if(substr(strtolower($domain), 0, 7) == "https://") $domain = substr($domain, 8);
	if(substr(strtolower($domain), 0, 4) == "www.") $domain = substr($domain, 4);
	//Look based on IP Address
	if(filter_var($domain, FILTER_VALIDATE_IP)) {
		$whoisservers = array(
			"whois.lacnic.net", // Latin America and Caribbean - returns data for ALL locations worldwide
			"whois.apnic.net", // Asia/Pacific only
			"whois.arin.net", // North America only
			"whois.ripe.net" // Europe, Middle East and Central Asia only
		);
		$results = array();
		foreach($whoisservers as $whoisserver) {
			$res = QueryWhoisServer($whoisserver, $domain);
			if($res && !in_array($res, $results)) {
				$results[$whoisserver]= $res;
			}
		}
		$result = "RESULTS FOUND: " . count($results);
		foreach($results as $whoisserver=>$res) {
			$result .= "\n\n-------------\nLookup results for " . $domain . " from " . $whoisserver . " server:\n\n" . $res;
		}
	}
	//Look based on Domain name
	elseif(preg_match("/^(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/i", $domain)) {
		$whoisservers = json_decode(file_get_contents('domain.json'), true);
		$domain_parts = explode(".", $domain);
		$tld = strtolower(array_pop($domain_parts));
		$whoisserver = $whoisservers[$tld][0];
		if(!$whoisserver) {
			return "Error: No appropriate Whois server found for $domain domain!";
		}
		$result = QueryWhoisServer($whoisserver, $domain);
		if(!$result) {
			return "Error: No results retrieved from $whoisserver server for $domain domain!";
		}
		else {
			while(strpos($result, "Whois Server:") !== FALSE){
				preg_match("/Whois Server: (.*)/", $result, $matches);
				$secondary = $matches[1];
				if($secondary) {
					$result = QueryWhoisServer($secondary, $domain);
					$whoisserver = $secondary;
				}
			}
		}
		$result = "$domain domain lookup results from $whoisserver server:\n\n" . $result;
	}
	else die("Invalid Input!");
	echo "<pre>\n" . $result . "\n</pre>\n";
}
?>
