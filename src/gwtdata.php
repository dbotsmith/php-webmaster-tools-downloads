<?php
/**
	 *  PHP class for downloading CSV files from Google Webmaster Tools.
	 *
	 *  This class does NOT require the Zend gdata package be installed
	 *  in order to run.
	 *
	 *  Copyright 2012 eyecatchUp UG. All Rights Reserved.
	 *
	 *  Licensed under the Apache License, Version 2.0 (the "License");
	 *  you may not use this file except in compliance with the License.
	 *  You may obtain a copy of the License at
	 *
	 *     http://www.apache.org/licenses/LICENSE-2.0
	 *
	 *  Unless required by applicable law or agreed to in writing, software
	 *  distributed under the License is distributed on an "AS IS" BASIS,
	 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	 *  See the License for the specific language governing permissions and
	 *  limitations under the License.
	 *
	 *  @author: Stephan Schmitz <eyecatchup@gmail.com>
	 *  @link:   https://code.google.com/p/php-webmaster-tools-downloads/
	 *  @link:   https://github.com/eyecatchup/php-webmaster-tools-downloads/
	 */

	 class GWTdata
	 {
		const HOST = "https://www.google.com";
		const SERVICEURI = "/webmasters/tools/";

		public $_language, $_tables, $_daterange, $_downloaded, $_skipped;
		private $_auth, $_logged_in;
		private $_http_client;
		private $_csv_handler;

		public function __construct()
		{
			$this->_auth = false;
			$this->_logged_in = false;
			$this->_language = "en";
			$this->_daterange = array("","");
			$this->_tables = array("TOP_PAGES", "TOP_QUERIES",
				"CRAWL_ERRORS", "CONTENT_ERRORS", "CONTENT_KEYWORDS",
				"INTERNAL_LINKS", "EXTERNAL_LINKS", "SOCIAL_ACTIVITY",
                "LATEST_BACKLINKS"
			);
			$this->_errTablesSort = array(0 => "http",
				1 => "not-found", 2 => "restricted-by-robotsTxt",
				3 => "unreachable", 4 => "timeout", 5 => "not-followed",
				"kAppErrorSoft-404s" => "soft404", "sitemap" => "in-sitemaps"
			);
			$this->_errTablesType = array(0 => "web-crawl-errors",
				1 => "mobile-wml-xhtml-errors", 2 => "mobile-chtml-errors",
				3 => "mobile-operator-errors", 4 => "news-crawl-errors"
			);
			$this->_downloaded = array();
			$this->_skipped = array();
			if (extension_loaded('curl'))
			{
			    $this->setHttpClient(array('GWTdata', 'curl_http_client'));
			}
			$this->setCsvHandler(array('GWTdata', 'file_csv_handler'));
		}

		/**
		 *  Sets content language.
		 *
		 *  @param $str     String   Valid ISO 639-1 language code, supported by Google.
		 */
			public function SetLanguage($str)
			{
				$this->_language = $str;
			}

		/**
		 *  Sets features that should be downloaded.
		 *
		 *  @param $arr     Array   Valid array values are:
		 *                          "TOP_PAGES", "TOP_QUERIES", "CRAWL_ERRORS", "CONTENT_ERRORS",
		 *                          "CONTENT_KEYWORDS", "INTERNAL_LINKS", "EXTERNAL_LINKS",
		 *                          "SOCIAL_ACTIVITY".
		 */
			public function SetTables($arr)
			{
				if(is_array($arr) && !empty($arr) && sizeof($arr) <= 2) {
					$valid = array("TOP_PAGES","TOP_QUERIES","CRAWL_ERRORS","CONTENT_ERRORS",
					  "CONTENT_KEYWORDS","INTERNAL_LINKS","EXTERNAL_LINKS","SOCIAL_ACTIVITY",
                      "LATEST_BACKLINKS");
					$this->_tables = array();
					for($i=0; $i < sizeof($arr); $i++) {
						if(in_array($arr[$i], $valid)) {
							array_push($this->_tables, $arr[$i]);
						} else { throw new Exception("Invalid argument given."); }
					}
				} else { throw new Exception("Invalid argument given."); }
			}

		/**
		 *  Sets daterange for download data.
		 *
		 *  @param $arr     Array   Array containing two ISO 8601 formatted date strings.
		 */
			public function SetDaterange($arr)
			{
				if(is_array($arr) && !empty($arr) && sizeof($arr) == 2) {
					if(self::IsISO8601($arr[0]) === true &&
					  self::IsISO8601($arr[1]) === true) {
						$this->_daterange = array(str_replace("-", "", $arr[0]),
						  str_replace("-", "", $arr[1]));
						return true;
					} else { throw new Exception("Invalid argument given."); }
				} else { throw new Exception("Invalid argument given."); }
			}

		/**
		 *  Returns array of downloaded filenames.
		 *
		 *  @return  Array   Array of filenames that have been written to disk.
		 */
			public function GetDownloadedFiles()
			{
				return $this->_downloaded;
			}

		/**
		 *  Returns array of downloaded filenames.
		 *
		 *  @return  Array   Array of filenames that have been written to disk.
		 */
			public function GetSkippedFiles()
			{
				return $this->_skipped;
			}

		/**
		 *  Checks if client has logged into their Google account yet.
		 *
		 *  @return Boolean  Returns true if logged in, or false if not.
		 */
			private function IsLoggedIn()
			{
				return $this->_logged_in;
			}

		/**
		 * Inject a callback which the GWTdata object can use to send HTTP requests
		 * 
		 * The intent is to remove the curl dependency. E.g. the callback could
		 * use Guzzle, or PHP stream wrappers. See callHttpClient() for the
		 * prototype of the callback.
		 * 
		 * @param callable $http_client
		 */
			public function setHttpClient(callable $http_client)
			{
			    $this->_http_client = $http_client;
			}

		/**
		 * Calls the closure that was set by setHttpClient()
		 * 
		 * This method has the same param and return type as
		 * the callback that is provided to setHttpClient().
		 * If http status code is not 200, or other error 
		 * e.g. if desired, when Content-Type doesn't match Accept header,
		 * the callback should throw an Exception which should
		 * be caught by the caller of GWTdata.
		 * GWTdata attempts to set the correct Accept headers including:
		 * text/csv,
		 * application/x-javascript for downloads list, 
		 * application/atom+xml for the sites list,
		 * text/plain for the LogIn token.
		 * for GetToken I haven't checked yet.
		 * 
		 * @param array $request          Looks like: ['url'=>'https://www.google.com...',
		 *                                             'method'=>'GET',
		 *                                             'body'=>string,
		 *                                             'headers'=>['Authorization' => 'GoogleLogin auth=...',
		 *                                                         'GData-Version' => '2',
		 *                                                         'Accept' => 'text/csv',
		 *                                                         'Header-name'=>string|array]]
		 * @return string|object|resource If object or resource, it should be castable to a string
		 */
			public function callHttpClient(array $request)
			{
			    return call_user_func($this->_http_client, $request);
			}
			
		/**
		 * Inject a callback which the GWTdata object can use to handle the csv data
		 * 
		 * The intent is to allow the caller of GWTdata methods
		 * to control what is done with the downloaded data
		 * rather than only write to files. E.g. the callback could
		 * write to a database, or transform and upload to another service.
		 * See callCsvHandler() for the prototype of the callback.
		 * 
		 * @param callable $csv_handler
		 */
			public function setCsvHandler(callable $csv_handler)
			{
			    $this->_csv_handler = $csv_handler;
			}

		/**
		* Calls the closure that was set by setCsvHandler()
		*
		* This method has the same param and return type as
		* the callback that is provided to setCsvHandler().
		*
		* @param string|object|resource $http_response
		*                               The response from the closure
		*                               that was set by setHttpClient()
		*
		* @param array   $downloadAttributes
		*                Keys may be different depending on the table, but include:
		*                'table' => e.g. TOP_QUERIES
		*                'site' => e.g. http://example.com/path/
		*                'downloadTStamp' => unix timestamp e.g. result from time()
		*                'dateBegin' => Start of date range requested. ISO 8601 (eg. '2012-01-01').
		*                'dateEnd' => End of date range requested. ISO 8601 (eg. '2012-01-01').
		*
		* @return String|Boolean  A transformed name for stored csv table if successful.
		*                         Should be realpath(self::targetFileName($downloadAttributes)) if
		*                         saved as csv file.
		*                         False means either $http_response had no data,
		*                         or there was an error trying to handle the
		*                         response. If this return value is not false,
		*                         it will be listed in GetDownloadedFiles(). Otherwise, the result of
		*                         self::targetFileName($downloadAttributes) will be listed in GetSkippedFiles(). 
		*/
			public function callCsvHandler($http_response, $downloadAttributes)
			{
			    return call_user_func($this->_csv_handler, $http_response, $downloadAttributes);
			}

		/**
		 *  Attempts to log into the specified Google account.
		 *
		 *  @param $email  String   User's Google email address.
		 *  @param $pwd    String   Password for Google account.
		 *  @return Boolean  Returns true when Authentication was successful,
		 *                   else false.
		 */
			public function LogIn($email, $pwd)
			{
			    $request = $this->getLogInRequest($email, $pwd);
			    $response = (string)$this->callHttpClient($request);
			    return $this->parseAuthToken($response);
			}
			
		/**
		 *  Get the request param for callHttpClient() for logging into the specified Google account.
		 *
		 *  @param $email  String   User's Google email address.
		 *  @param $pwd    String   Password for Google account.
		 *  @return array  Returns array with keys needed by callHttpClient()
		 */
			public function getLogInRequest($email, $pwd)
			{
			    $url = self::HOST . "/accounts/ClientLogin";
				$postRequest = array(
					'accountType' => 'HOSTED_OR_GOOGLE',
					'Email' => $email,
					'Passwd' => $pwd,
					'service' => "sitemaps",
					'source' => "Google-WMTdownloadscript-0.1-php"
				);
				$body = http_build_query($postRequest);
				$method = 'POST';
				$headers['Accept'] = 'text/plain';
				return compact('url', 'method', 'headers', 'body');
			}
			
		/**
		*  Parse out the auth token from login response.
		*
		*  @param $responseBody  String   body of response from Google login request.
		*  @return Boolean  Returns true when Authentication was successful,
		*                   else false.
		*/
			public function parseAuthToken($responseBody) {
					preg_match('/Auth=(.*)/', $responseBody, $match);
					if(isset($match[1])) {
						$this->_auth = $match[1];
						$this->_logged_in = true;
						return true;
					} else { return false; }
			}

		/**
		 *  Converts the relative url to the request structure needed by callHttpClient()
		 *
		 *  @param $url    String   URL for the GET request.
		 *  @param $accept String   mime type expected. Probably error if Content-Type of response is not compatible.
		 *  @return array  Returns array with keys needed by callHttpClient()
		 */
			public function GetDataRequest($url, $accept = '*/*')
			{
					$url = self::HOST . $url;
					$headers = array(
					    'Authorization' => "GoogleLogin auth={$this->_auth}",
					    'GData-Version' => '2',
					    'Accept-Encoding' => '1',
					);
					if ($accept) $headers['Accept'] = $accept;
					$method = 'GET';
					return compact ('url', 'method', 'headers');
			}

		/**
		 * Default for _http_client. Function prototype matches callHttpClient().
		 *
		 * @param array $request          Looks like: ['url'=>'https://www.google.com...',
		 *                                             'method'=>'GET',
		 *                                             'body'=>string,
		 *                                             'headers'=>['Authorization' => 'GoogleLogin auth=...',
		 *                                                         'GData-Version' => '2',
		 *                                                         'Accept' => 'text/csv',
		 *                                                         'Header-name'=>string|array]]
		 * @return string|object|resource If object or resource, it should be castable to a string
		 */
			public static function curl_http_client($request)
			{
				$defaults = array(
				    'url' => null,
				    'method' => 'GET',
				    'headers' => array(),
				    'body' => null);
				extract(array_merge($defaults, array_intersect_key($request, $defaults)));
				if ( ! $url ) throw new Exception("No url given");
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $url);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
				curl_setopt($ch, CURLINFO_HEADER_OUT, true);
				if ($headers)
				{
				    $curl_headers = array();
				    $implode_header = function($value, $key) use (&$curl_headers)
				    {
				        $curl_headers[] = "$key: " . implode(',', (array)$value);
				    };
				    array_walk($headers, $implode_header);
				    curl_setopt($ch, CURLOPT_HTTPHEADER, $curl_headers);
				}
				if ($method == 'POST')
				{
				    curl_setopt($ch, CURLOPT_POST, true);
				    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
				}
				$result = curl_exec($ch);
				$info = curl_getinfo($ch);
				curl_close($ch);
				if ($info['http_code']!=200) throw new Exception("HTTP status not 200");
				return $result;
			}

		/**
		 *  Gets all available sites from Google Webmaster Tools account.
		 *
		 *  @return Mixed  Array with all site URLs registered in GWT account,
		 *                 or false (Boolean) if request failed.
		 */
			public function GetSites()
			{
				if(self::IsLoggedIn() === true) {
					$request = $this->GetSitesRequest();
					$response = (string)$this->callHttpClient($request);
					return $this->parseSites($response);
				} else {
				    return false;
				}
			}

		/**
		 *  Get the request param for callHttpClient() to get a list of
		 *  all available sites from Google Webmaster Tools account.
		 *
		 *  @return array  Returns array with keys needed by callHttpClient()
		 */
			public function GetSitesRequest()
			{
					return $this->GetDataRequest(self::SERVICEURI."feeds/sites/", 'application/atom+xml');
			}

		/**
		 *  Gets all available sites from Google Webmaster Tools account.
		 *
		 *  @param $feed String  xml document - the response from sending the sites request
		 *  @return Mixed  Array with all site URLs registered in GWT account,
		 *                 or false (Boolean) if request failed.
		 */
			public function parseSites($feed)
			{
			        if($feed !== false) {
			            $sites = array();
			            $doc = new DOMDocument();
			            $doc->loadXML($feed);
			            foreach ($doc->getElementsByTagName('entry') as $node) {
			                array_push($sites,
			                $node->getElementsByTagName('title')->item(0)->nodeValue);
			            }
			            return $sites;
			        } else { return false; }
			}
			
		/**
		 *  Gets the download links for an available site
		 *  from the Google Webmaster Tools account.
		 *
		 *  @param $url    String   Site URL registered in GWT.
		 *  @return Mixed  Array with keys TOP_PAGES and TOP_QUERIES,
		 *                 or false (Boolean) when Authentication fails.
		 */
			public function GetDownloadUrls($url)
			{
				if(self::IsLoggedIn() === true) {
				    $request = $this->GetDownloadUrlsRequest($url);
				    $downloadList = (string)$this->callHttpClient($request);
					return json_decode($downloadList, true);
				} else { return false; }
			}

		/**
		 *  Get the request param for callHttpClient() to download links
		 *  for an available site
		 *  from the Google Webmaster Tools account.
		 *
		 *  @param $url    String   Site URL registered in GWT.
		 *  @return array  Returns array with keys needed by callHttpClient()
		 */
			public function GetDownloadUrlsRequest($url)
			{
			        $_url = sprintf(self::SERVICEURI."downloads-list?hl=%s&siteUrl=%s",
			            $this->_language,
			            urlencode($url));
			        return $this->GetDataRequest($_url,'application/x-javascript');
			}
				
				
		/**
		 *  Downloads the file based on the given URL.
		 *
		 *  @param $site    String   Site URL available in GWT Account.
		 *  @param $savepath  String   Optional path to save CSV to (no trailing slash!).
		 */
			public function DownloadCSV($site, $savepath=".")
			{
				if(self::IsLoggedIn() === true) {
					$downloadUrls = self::GetDownloadUrls($site);
					$downloadAttributes['site'] = $site;
					$downloadAttributes['downloadTStamp'] = time();
					$tables = $this->_tables;
					foreach($tables as $table) {
						if($table=="CRAWL_ERRORS") {
							self::DownloadCSV_CrawlErrors($site, $savepath);
						}
						elseif($table=="CONTENT_ERRORS") {
							self::DownloadCSV_XTRA($site, $savepath,
							  "html-suggestions", "\)", "CONTENT_ERRORS", "content-problems-dl");
						}
						elseif($table=="CONTENT_KEYWORDS") {
							self::DownloadCSV_XTRA($site, $savepath,
							  "keywords", "\)", "CONTENT_KEYWORDS", "content-words-dl");
						}
						elseif($table=="INTERNAL_LINKS") {
							self::DownloadCSV_XTRA($site, $savepath,
							  "internal-links", "\)", "INTERNAL_LINKS", "internal-links-dl");
						}
						elseif($table=="EXTERNAL_LINKS") {
							self::DownloadCSV_XTRA($site, $savepath,
							  "external-links-domain", "\)", "EXTERNAL_LINKS", "external-links-domain-dl");
						}
						elseif($table=="SOCIAL_ACTIVITY") {
							self::DownloadCSV_XTRA($site, $savepath,
							  "social-activity", "x26", "SOCIAL_ACTIVITY", "social-activity-dl");
						}
                        elseif($table=="LATEST_BACKLINKS") {
                            self::DownloadCSV_XTRA($site, $savepath,
							  "external-links-domain", "\)", "LATEST_BACKLINKS", "backlinks-latest-dl");
                        }
						else {
							$finalUrl = $downloadUrls[$table] ."&prop=ALL&db=%s&de=%s&more=true";
							$finalUrl = sprintf($finalUrl, $this->_daterange[0], $this->_daterange[1]);
							$downloadAttributes['savepath'] = $savepath;
							$downloadAttributes['table'] = $table;
							$downloadAttributes['dateBegin'] = $this->_daterange[0];
							$downloadAttributes['dateEnd'] = $this->_daterange[1];
							self::SaveData($finalUrl, $downloadAttributes);
						}
					}
				} else { return false; }
			}

		/**
		 *  Downloads "unofficial" downloads based on the given URL.
		 *
		 *  @param $site    String   Site URL available in GWT Account.
		 *  @param $savepath  String   Optional path to save CSV to (no trailing slash!).
		 */
			public function DownloadCSV_XTRA($site, $savepath=".", $tokenUri, $tokenDelimiter, $filenamePrefix, $dlUri)
			{
				if(self::IsLoggedIn() === true) {
					$uri = self::SERVICEURI . $tokenUri . "?hl=%s&siteUrl=%s";
					$_uri = sprintf($uri, $this->_language, $site);
					$token = self::GetToken($_uri, $tokenDelimiter, $dlUri);
					$downloadAttributes['site'] = $site;
					$downloadAttributes['downloadTStamp'] = time();
					$downloadAttributes['savepath'] = $savepath;
					$downloadAttributes['table'] = $filenamePrefix;
					$downloadAttributes['dateBegin'] = $this->_daterange[0];
					$downloadAttributes['dateEnd'] = $this->_daterange[1];
					$url = self::SERVICEURI . $dlUri . "?hl=%s&siteUrl=%s&security_token=%s&prop=ALL&db=%s&de=%s&more=true";
					$_url = sprintf($url, $this->_language, $site, $token, $this->_daterange[0], $this->_daterange[1]);
					self::SaveData($_url, $downloadAttributes);
				} else { return false; }
			}

		/**
		 *  Downloads the Crawl Errors file based on the given URL.
		 *
		 *  @param $site    String   Site URL available in GWT Account.
		 *  @param $savepath  String   Optional: Path to save CSV to (no trailing slash!).
		 *  @param $separated Boolean  Optional: If true, the method saves separated CSV files
		 *                             for each error type. Default: Merge errors in one file.
		 */
			public function DownloadCSV_CrawlErrors($site, $savepath=".", $separated=false)
			{
				if(self::IsLoggedIn() === true) {
					$type_param = "we";
					$downloadAttributes['site'] = $site;
					$downloadAttributes['downloadTStamp'] = time();
					if($separated) {
						foreach($this->_errTablesSort as $sortid => $sortname) {
							foreach($this->_errTablesType as $typeid => $typename) {
								if($typeid == 1) {
									$type_param = "mx";
								} else if($typeid == 2) {
									$type_param = "mc";
								} else {
									$type_param = "we";
								}
								$uri = self::SERVICEURI."crawl-errors?hl=en&siteUrl=$site&tid=$type_param";
								$token = self::GetToken($uri,"x26");
								$downloadAttributes['savepath'] = $savepath;
								$downloadAttributes['table'] = 'CRAWL_ERRORS';
								$downloadAttributes['typename'] = $typename;
								$downloadAttributes['sortname'] = $sortname;
								$downloadAttributes['dateBegin'] = $this->_daterange[0];
								$downloadAttributes['dateEnd'] = $this->_daterange[1];
								$url = self::SERVICEURI."crawl-errors-dl?hl=%s&siteUrl=%s&security_token=%s&type=%s&sort=%s";
								$_url = sprintf($url, $this->_language, $site, $token, $typeid, $sortid);
								self::SaveData($_url, $downloadAttributes);
							}
						}
					}
					else {
						$uri = self::SERVICEURI."crawl-errors?hl=en&siteUrl=$site&tid=$type_param";
						$token = self::GetToken($uri,"x26");
						$downloadAttributes['savepath'] = $savepath;
						$downloadAttributes['table'] = 'CRAWL_ERRORS';
						$downloadAttributes['dateBegin'] = $this->_daterange[0];
						$downloadAttributes['dateEnd'] = $this->_daterange[1];
						$url = self::SERVICEURI."crawl-errors-dl?hl=%s&siteUrl=%s&security_token=%s&type=0";
						$_url = sprintf($url, $this->_language, $site, $token);
						self::SaveData($_url, $downloadAttributes);
					}
				} else { return false; }
			}

		/**
		 *  Saves data to a CSV file based on the given URL.
		 *
		 *  @param $finalUrl   String   CSV Download URI.
		 *  @param $downloadAttributes  array Attributes used by targetFileName()
		 *                                    and others can be used by the csvHandler.
		 */
			private function SaveData($finalUrl, $downloadAttributes)
			{
			    $request = $this->GetDataRequest($finalUrl, 'text/csv');
			    $response = $this->callHttpClient($request);
				$stored_name = $this->callCsvHandler($response, $downloadAttributes);
				if ($stored_name)
				{
					array_push($this->_downloaded, $stored_name);
					return true;
				} else {
			    $targetFileName = self::targetFileName($downloadAttributes);
			    array_push($this->_skipped, $targetFileName);
					return false;
				}
			}

		/**
		* Build relative filename from downloadAttributes
		* 
		* @param array   $downloadAttributes
		*                Keys may be different depending on the table, but include:
		*                'table' => e.g. TOP_QUERIES
		*                'site' => e.g. http://example.com/path/
		*                'downloadTStamp' => unix timestamp e.g. result from time()
		*                'dateBegin' => Start of date range requested. ISO 8601 (eg. '2012-01-01').
		*                'dateEnd' => End of date range requested. ISO 8601 (eg. '2012-01-01').
		* 
		*/
		public static function targetFileName($downloadAttributes)
		{
		    $downloadAttrDefaults = array(
		        'table' => null,
		        'site' => null,
		        'downloadTStamp' => null,
		        'dateBegin' => null,
		        'dateEnd' => null,
		        'savepath' => '.',
		        'typename' => null,
		        'sortname' => null,
		    );
		    extract(array_merge($downloadAttrDefaults, array_intersect_key($downloadAttributes, $downloadAttrDefaults)));
		     
		    $siteStr = preg_replace('/[^A-Za-z0-9_\-.]+/', '_', $site);
		    $tstamp = date("Ymd-His", $downloadTStamp);
		    $filename = implode('-', array_filter(compact('table', 'typename', 'sortname', 'siteStr', 'tstamp')));
		    return "$savepath/$filename.csv";
		}

		/**
		 * Default for _csv_handler. Function prototype matches callCsvHandler().
		 *
		 * @param string|object|resource $http_response
		 *                               The response from the closure
		 *                               that was set by setHttpClient()
		 *
		* @param array   $downloadAttributes
		*                Keys may be different depending on the table, but include:
		*                'table' => e.g. TOP_QUERIES
		*                'site' => e.g. http://example.com/path/
		*                'downloadTStamp' => unix timestamp e.g. result from time()
		*                'dateBegin' => Start of date range requested. ISO 8601 (eg. '2012-01-01').
		*                'dateEnd' => End of date range requested. ISO 8601 (eg. '2012-01-01').
		 *
		 * @return String|Boolean  A transformed name for stored csv table if successful.
		 *                         Should be realpath(self::targetFileName($downloadAttributes)) if
		 *                         saved as csv file.
		 *                         False means either $http_response had no data,
		 *                         or there was an error trying to handle the
		 *                         response. If this return value is not false,
		 *                         it will be listed in GetDownloadedFiles(). Otherwise, the result of
		 *                         self::targetFileName($downloadAttributes) will be listed in GetSkippedFiles(). 
		 */
			public static function file_csv_handler($http_response, $downloadAttributes)
			{
			    $targetFileName = self::targetFileName($downloadAttributes);
			    $data = (string)$http_response;
			    if(strlen($data) > 1 && file_put_contents($targetFileName, utf8_decode($data)))
			    {
			        return realpath($targetFileName);
			    }
			    return false;
			}
			
		/**
		 *  Regular Expression to find the Security Token for a download file.
		 *
		 *  @param $uri        String   A Webmaster Tools Desktop Service URI.
		 *  @param $delimiter  String   Trailing delimiter for the regex.
		 *  @return  String    Returns a security token.
		 */
			private function GetToken($uri, $delimiter, $dlUri='')
			{
				$matches = array();
				$request = self::GetDataRequest($uri); //What should $accept parameter be?
				$tmp = (string)$this->callHttpClient($request);
				preg_match_all("#$dlUri.*?46security_token(.*?)$delimiter#si", $tmp, $matches);
				return isset($matches[1][0]) ? substr($matches[1][0],3,-1) : '';
			}

		/**
		 *  Validates ISO 8601 date format.
		 *
		 *  @param $str      String   Valid ISO 8601 date string (eg. 2012-01-01).
		 *  @return  Boolean   Returns true if string has valid format, else false.
		 */
			private function IsISO8601($str)
			{
				$stamp = strtotime($str);
				return (is_numeric($stamp) && checkdate(date('m', $stamp),
					  date('d', $stamp), date('Y', $stamp))) ? true : false;
			}
	 }
?>
