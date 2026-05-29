$Keywords = @("APT", "campaign", "Advanced Persistent Threat", "Zero-day", "Ransomware", "Ransomware", "Lateral movement", "Persistence",  "Evasion",  "Data leaks",  "Privilege Escalation",  "Trojan",  "Infostealer",  "Botnet",  "Banking Trojan",  "spear phishing",  "social engineering",  "credential dumping",  "EDR bypass",  "DLL sideloading",  "Process Injection",  "Reflective DLL",  "sandbox escape",  "fileless malware",  "in-memory malware",  "supply chain",  "compromise",  "breach", "Malware", "CVE", "Exploit", "vulnerability", "phishing", "initial access")

# MITRE ATT&CK Technique Keywords Mapping
$MitreKeywords = @{
    "T1566" = @{
        Name = "Phishing"
        Keywords = @("phishing", "spear phishing", "malicious email", "email lure", "attachment", "spoofed email", "fake invoice")
    }

    "T1059" = @{
        Name = "Command and Scripting Interpreter"
        Keywords = @("powershell", "pwsh", "ps1", "cmd.exe", "command line", "bash", "sh", "zsh", "python", "python script", "wscript", "cscript", "javascript", "vbscript")
    }

    "T1055" = @{
        Name = "Process Injection"
        Keywords = @("process injection", "dll injection", "reflective loading", "hollowing", "process hollowing", "thread injection", "apc injection")
    }

    "T1190" = @{
        Name = "Exploit Public-Facing Application"
        Keywords = @("web exploit", "sql injection", "sqli", "rce", "remote code execution", "zero-day", "path traversal", "file upload exploit")
    }

    "T1078" = @{
        Name = "Valid Accounts"
        Keywords = @("compromised credentials", "stolen password", "valid account", "successful logon", "unauthorized login", "credential reuse")
    }

    "T1021" = @{
        Name = "Remote Services"
        Keywords = @("rdp", "remote desktop", "ssh", "smb", "psexec", "winrm", "remote login", "vnc", "teamviewer", "anydesk")
    }

    "T1105" = @{
        Name = "Ingress Tool Transfer"
        Keywords = @("download payload", "curl", "wget", "bitsadmin", "file transfer", "dropper", "stager", "malware download")
    }

    "T1486" = @{
        Name = "Data Encrypted for Impact"
        Keywords = @("ransomware", "encryption", "encrypted files", "crypto locker", "ransom note", "file encryption")
    }

    "T1082" = @{
        Name = "System Information Discovery"
        Keywords = @("system info", "host discovery", "os version", "hardware info", "environment discovery")
    }

    "T1071" = @{
        Name = "Application Layer Protocol"
        Keywords = @("c2", "command and control", "c&c", "http c2", "dns tunneling", "https beacon", "websocket")
    }

    "T1083" = @{
        Name = "File and Directory Discovery"
        Keywords = @("file search", "directory listing", "dir listing", "file enumeration", "tree", "find", "ls", "get-childitem")
    }

    "T1574" = @{
        Name = "Hijack Execution Flow"
        Keywords = @("dll hijacking", "search order hijack", "path interception", "side loading")
    }

    "T1003" = @{
        Name = "OS Credential Dumping"
        Keywords = @("mimikatz", "lsass dump", "procdump lsass", "sam dump", "credential dumping", "sekurlsa")
    }

    "T1027" = @{
        Name = "Obfuscated Files or Information"
        Keywords = @("obfuscation", "encoded", "base64 payload", "packed malware", "steganography", "encrypted payload")
    }

    "T1070" = @{
        Name = "Indicator Removal"
        Keywords = @("clear logs", "log deletion", "wevtutil", "anti-forensics", "clear event log")
    }

    "T1204" = @{
        Name = "User Execution"
        Keywords = @("user clicked", "user opened", "malicious macro", "document execution", "unsafe download")
    }

    "T1053" = @{
        Name = "Scheduled Task/Job"
        Keywords = @("schtasks", "cron job", "task scheduler", "at command", "persistent task")
    }

    "T1562" = @{
        Name = "Impair Defenses"
        Keywords = @("disable antivirus", "tamper protection", "disable firewall", "stop security service", "endpoint protection disabled")
    }

    "T1087" = @{
        Name = "Account Discovery"
        Keywords = @("user enumeration", "net user", "active directory users", "whoami", "account discovery")
    }

    "T1018" = @{
        Name = "Remote System Discovery"
        Keywords = @("network scan", "nmap", "ping sweep", "port scan", "host scan", "net view")
    }
}


$Feeds = @(
    "https://www.thehackernews.com/feeds/posts/default",
    "https://www.securelist.com/feed/",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.welivesecurity.com/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://www.mandiant.com/resources/blog/rss.xml",
    "https://research.checkpoint.com/feed/",
    "https://blog.badsectorlabs.com/feeds/all.atom.xml",
    "https://cyberbuilders.substack.com/feed",
    "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "https://blogs.cisco.com/security/feed",
    "http://feeds.trendmicro.com/TrendMicroResearch",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.techrepublic.com/rssfeeds/topic/cybersecurity/",
    "https://www.proofpoint.com/us/rss.xml",
    "https://www.imperva.com/blog/feed/",
    "https://heimdalsecurity.com/blog/feed/",
    "https://www.yeswehack.com/rss.xml",
    "https://feeds.feedburner.com/GoogleOnlineSecurityBlog",
    "https://heimdalsecurity.com/blog/feed/"
    "https://any.run/cybersecurity-blog/feed/",
    "https://www.exploitone.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://hackread.com/feed/",
    "https://www.hackmageddon.com/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://krebsonsecurity.com/feed/",
    "https://www.zdnet.com/news/rss.xml",
    "https://blog.0patch.com/feeds/posts/default",
    "https://www.bitdefender.com/nuxt/api/en-us/rss/labs/",
    "https://feeds.feedburner.com/feedburner/Talos",
    "https://blog.cloudflare.com/tag/security/rss",
    "https://projectzero.google/feed.xml",
    "https://www.malwarebytes.com/blog/feed/index.xml",
    "https://www.cisecurity.org/feed/advisories",
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://nao-sec.org/feed",
    "https://www.reddit.com/r/cybersecurity/.rss",
    "https://www.reddit.com/r/netsec/.rss",
    "https://www.reddit.com/r/blueteamsec/.rss"
    "https://www.reddit.com/r/purpleteamsec/.rss"
    "https://www.reddit.com/r/redteamsec/.rss"
    "https://blog.qualys.com/feed",
    "https://blog.quarkslab.com/feeds/all.rss.xml",
    "https://sensepost.com/rss.xml",
    "https://www.sentinelone.com/labs/feed/",
    "https://www.darkreading.com/rss.xml"
    "https://cybersecuritynews.com/feed/"
)

$VulnDays = 7  

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$DesktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
$CsvPath = Join-Path $DesktopPath "APT_Report_$Timestamp.csv"
$HtmlPath = Join-Path $DesktopPath "APT_Report_$Timestamp.html"

$Results = New-Object System.Collections.Generic.List[PSObject]

Write-Host "`n=== APT Intelligence Feed Monitor ===" -ForegroundColor Cyan
Write-Host "This script will check for duplicate links from a previous report." -ForegroundColor Yellow
Write-Host "`nDo you want to load a previous CSV file to avoid duplicates? (Y/N)" -ForegroundColor Green
$loadPrevious = Read-Host "Enter choice"

$ExistingLinks = @{}
$PreviousCsvPath = $null
$TrackNewLinks = $false

if ($loadPrevious -eq 'Y' -or $loadPrevious -eq 'y') {
    $TrackNewLinks = $true
    Write-Host "`nPlease enter the full path to the previous CSV file:" -ForegroundColor Cyan
    Write-Host "Example: C:\Users\YourName\Desktop\APT_Report_2025-01-11_10-30.csv" -ForegroundColor Gray
    $PreviousCsvPath = Read-Host "CSV Path"
    
    if (Test-Path $PreviousCsvPath) {
        Write-Host "Loading previous data..." -ForegroundColor Yellow
        try {
            $PreviousData = Import-Csv -Path $PreviousCsvPath -Encoding UTF8
            foreach ($item in $PreviousData) {
                if ($item.Link -and -not $ExistingLinks.ContainsKey($item.Link)) {
                    $ExistingLinks[$item.Link] = $true
                }
            }
            Write-Host "Loaded $($ExistingLinks.Count) existing links for deduplication." -ForegroundColor Green
        } catch {
            Write-Host "Error reading previous CSV: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Continuing without deduplication..." -ForegroundColor Yellow
            $ExistingLinks = @{}
        }
    } else {
        Write-Host "File not found. Continuing without deduplication..." -ForegroundColor Red
        $ExistingLinks = @{}
    }
} else {
    Write-Host "Skipping deduplication. All found links will be treated as existing content." -ForegroundColor Yellow
}

function Get-AllTextContent {
    param($Item)
    $textParts = @()
    
    $fieldsToCheck = @(
        'title', 'description', 'summary', 'content', 
        'encoded', 'contentEncoded', 'content:encoded',
        '#text', 'subtitle', 'rights', 'category'
    )
    
    foreach ($field in $fieldsToCheck) {
        try {
            if ($Item.PSObject.Properties[$field]) {
                $value = $Item.$field
                if ($value -is [string] -and $value.Trim() -ne "") {
                    $textParts += $value
                } elseif ($value -is [System.Xml.XmlElement]) {
                    $textParts += $value.InnerText
                } elseif ($value -is [array]) {
                    foreach ($v in $value) {
                        if ($v -is [string]) {
                            $textParts += $v
                        } elseif ($v.InnerText) {
                            $textParts += $v.InnerText
                        }
                    }
                }
            }
        } catch {
            continue
        }
    }
    
    try {
        if ($Item.'content:encoded') {
            $textParts += $Item.'content:encoded'
        }
    } catch { }
    
    $combinedText = $textParts -join " "
    $combinedText = $combinedText -replace '<[^>]+>', ' '
    $combinedText = $combinedText -replace '&nbsp;', ' '
    $combinedText = $combinedText -replace '&amp;', '&'
    $combinedText = $combinedText -replace '&lt;', '<'
    $combinedText = $combinedText -replace '&gt;', '>'
    $combinedText = $combinedText -replace '&quot;', '"'
    $combinedText = $combinedText -replace '&#39;', "'"
    $combinedText = $combinedText -replace '\s+', ' '
    
    return $combinedText.Trim()
}

function Get-MitreTechniques {
    param([string]$Text)
    
    $detectedTechniques = @()
    
    foreach ($techniqueId in $MitreKeywords.Keys) {
        $technique = $MitreKeywords[$techniqueId]
        foreach ($keyword in $technique.Keywords) {
            if ($Text -match "(?i)\b$keyword\b") {
                $detectedTechniques += "$techniqueId - $($technique.Name)"
                break
            }
        }
    }
    
    return $detectedTechniques | Sort-Object -Unique
}


function Get-ItemLink {
    param($Item, $FeedUrl)
    $extractedLink = $null
    
    # Special handling for 0patch blog
    if ($FeedUrl -match '0patch\.com') {
        if ($Item.link -and $Item.link -is [string] -and $Item.link -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/' -and $Item.link -notmatch '/feeds/|/comments/') {
            return $Item.link.Trim()
        }
        
        if ($Item.guid) {
            $guidText = if ($Item.guid -is [string]) { $Item.guid } else { $Item.guid.'#text' }
            if ($guidText -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/[^/]+\.html') {
                return $guidText.Trim()
            }
        }
        
        $contentToSearch = ""
        if ($Item.content) { 
            if ($Item.content -is [string]) {
                $contentToSearch += $Item.content 
            } else {
                $contentToSearch += $Item.content.InnerText
            }
        }
        if ($Item.description) { 
            if ($Item.description -is [string]) {
                $contentToSearch += " " + $Item.description 
            } else {
                $contentToSearch += " " + $Item.description.InnerText
            }
        }
        
        if ($contentToSearch -match 'href="(https?://blog\.0patch\.com/\d{4}/\d{2}/[^"]+\.html)"') {
            return $matches[1].Trim()
        }
    }
    
    if ($FeedUrl -match 'any\.run') {
        if ($Item.link) {
            if ($Item.link -is [string]) {
                $extractedLink = $Item.link
            } elseif ($Item.link.'#text') {
                $extractedLink = $Item.link.'#text'
            } elseif ($Item.link.href) {
                $extractedLink = $Item.link.href
            }
        }
        
        if (-not $extractedLink -and $Item.guid) {
            if ($Item.guid -is [string]) {
                $extractedLink = $Item.guid
            } elseif ($Item.guid.'#text') {
                $extractedLink = $Item.guid.'#text'
            }
        }
        
        if (-not $extractedLink -and $Item.id) {
            $extractedLink = $Item.id
        }
        
        if ($extractedLink) {
            if ($extractedLink -match '^/') {
                $extractedLink = "https://any.run" + $extractedLink
            } elseif ($extractedLink -match '^cybersecurity-blog') {
                $extractedLink = "https://any.run/" + $extractedLink
            } elseif ($extractedLink -match '^\?p=') {
                $extractedLink = "https://any.run/cybersecurity-blog/" + $extractedLink
            }
            
            if ($extractedLink -match '^https?://any\.run/' -and $extractedLink -notmatch '\.xml$|/feed/?$') {
                return $extractedLink.Trim()
            }
        }
        
        $contentToSearch = ""
        if ($Item.description) { 
            $contentToSearch += if ($Item.description -is [string]) { $Item.description } else { $Item.description.InnerText }
        }
        if ($Item.content) { 
            $contentToSearch += " " + (if ($Item.content -is [string]) { $Item.content } else { $Item.content.InnerText })
        }
        
        if ($contentToSearch -match 'href="(https?://any\.run/[^"]+)"') {
            return $matches[1].Trim()
        }
    }
    
    if ($FeedUrl -match 'reddit\.com') {
        $redditPostLink = $null
        
        if ($Item.link -and $Item.link -match 'reddit\.com/r/[^/]+/comments/') {
            $redditPostLink = $Item.link
        } elseif ($Item.id -and $Item.id -match 'reddit\.com/r/[^/]+/comments/') {
            $redditPostLink = $Item.id
        } elseif ($Item.guid) {
            $guidValue = if ($Item.guid -is [string]) { $Item.guid } else { $Item.guid.'#text' }
            if ($guidValue -and $guidValue -match 'reddit\.com/r/[^/]+/comments/') {
                $redditPostLink = $guidValue
            }
        }
        
        if (-not $redditPostLink) {
            $contentToSearch = ""
            if ($Item.content) {
                $contentToSearch += if ($Item.content -is [string]) { $Item.content } else { $Item.content.InnerText }
            }
            if ($Item.description) {
                $contentToSearch += " " + (if ($Item.description -is [string]) { $Item.description } else { $Item.description.InnerText })
            }
            
            if ($contentToSearch) {
                if ($contentToSearch -match 'href="(https?://[^"]*reddit\.com/r/[^/]+/comments/[^"]*)"') {
                    $redditPostLink = $matches[1].Trim()
                }
                
                if (-not $redditPostLink -and $contentToSearch -match '(https?://[^\s<>"]*reddit\.com/r/[^/]+/comments/[^\s<>"]*)') {
                    $redditPostLink = $matches[1].Trim()
                }
            }
        }
        
        if ($redditPostLink) {
            return $redditPostLink.Trim()
        }
        
        return $null
    }
    
    $linkSources = @(
        { $Item.link },
        { $Item.guid },
        { $Item.id },
        { $Item.url },
        { $Item.'feedburner:origLink' },
        { $Item.origLink }
    )
    
    foreach ($source in $linkSources) {
        try {
            $value = & $source
            if ($value) {
                if ($value -is [string]) {
                    if ($value -match '^https?://' -and 
                        $value -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                        $extractedLink = $value
                        break
                    }
                }
                elseif ($value.href) {
                    if ($value.href -match '^https?://' -and 
                        $value.href -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                        $extractedLink = $value.href
                        break
                    }
                }
                elseif ($value.'#text') {
                    if ($value.'#text' -match '^https?://' -and 
                        $value.'#text' -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                        $extractedLink = $value.'#text'
                        break
                    }
                }
                elseif ($value.InnerText) {
                    if ($value.InnerText -match '^https?://' -and 
                        $value.InnerText -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                        $extractedLink = $value.InnerText
                        break
                    }
                }
                elseif ($value -is [array]) {
                    foreach ($linkItem in $value) {
                        if ($linkItem -is [string] -and 
                            $linkItem -match '^https?://' -and 
                            $linkItem -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                            $extractedLink = $linkItem
                            break
                        } elseif ($linkItem.href -and 
                                  $linkItem.href -match '^https?://' -and 
                                  $linkItem.href -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                            $extractedLink = $linkItem.href
                            break
                        }
                    }
                    if ($extractedLink) { break }
                }
            }
        } catch {
            continue
        }
    }
    
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'cisa\.gov') {
        if ($Item.id -or $Item.guid) {
            $advisoryId = if ($Item.id) { $Item.id } else { $Item.guid }
            if ($advisoryId -match '(AA|ICSA?|ICS-?ALERT|CSAF)-\d{2}-\d{3,6}') {
                $extractedLink = "https://www.cisa.gov/news-events/cybersecurity-advisories/$advisoryId"
            }
        }
    }
    
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'talosintelligence|feedburner/Talos') {
        if ($Item.description -match 'href="(https?://[^"]+)"') {
            $extractedLink = $matches[1]
        }
    }
    
    if (-not $extractedLink -or 
        $extractedLink -match '\.xml$|/feed/?$|/rss/?$|/feeds/.*comments|/comments/' -or 
        $extractedLink -eq $FeedUrl) {
        $extractedLink = $FeedUrl
    }
    
    return $extractedLink.Trim()
}

Write-Host "`n[*] Scraping RSS Feeds..." -ForegroundColor Cyan
Write-Host "Total Feeds: $($Feeds.Count)`n" -ForegroundColor Yellow

$CurrentFeed = 0
$TotalFeeds = $Feeds.Count
$NewLinksCount = 0
$DuplicatesSkipped = 0

foreach ($url in $Feeds) {
    $CurrentFeed++
    $PercentComplete = [math]::Round(($CurrentFeed / $TotalFeeds) * 100)
    Write-Progress -Activity "Scanning RSS Feeds" -Status "Processing $CurrentFeed of $TotalFeeds ($PercentComplete%)" -PercentComplete $PercentComplete
    
    $FeedName = ([System.Uri]$url).Host
    Write-Host "[$CurrentFeed/$TotalFeeds] Checking: $FeedName" -ForegroundColor Gray -NoNewline
    
    try {
        $webRequest = $null
        $fetchSuccess = $false

        # --- Attempt 1: Standard request with browser User-Agent ---
        $userAgents = @(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (compatible; Feedfetcher-Google; +http://www.google.com/feedfetcher.html)",
            "FeedBurner/1.0 (http://www.FeedBurner.com)"
        )

        foreach ($agent in $userAgents) {
            try {
                # Build referer from feed URL host
                $feedHost = ([System.Uri]$url).Scheme + "://" + ([System.Uri]$url).Host
                $webRequest = Invoke-WebRequest -Uri $url -TimeoutSec 30 -UseBasicParsing -Headers @{
                    "User-Agent"      = $agent
                    "Accept"          = "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
                    "Accept-Language" = "en-US,en;q=0.9"
                    "Cache-Control"   = "no-cache"
                    "Referer"         = $feedHost
                }
                $fetchSuccess = $true
                break
            } catch {
                $errMsg = $_.Exception.Message
                # Timeout: retry with next agent
                if ($errMsg -match "timed out|timeout|TaskCanceledException") {
                    Start-Sleep -Seconds 2
                    continue
                }
                # 403 Forbidden: try next User-Agent (some sites block bots)
                if ($errMsg -match "403|Forbidden") {
                    Start-Sleep -Seconds 1
                    continue
                }
                # 404/401/410 - permanently gone, no point retrying
                if ($errMsg -match "404|401|410|Not Found|Unauthorized|Gone") {
                    Write-Host " - Unavailable ($errMsg)" -ForegroundColor DarkYellow
                    break
                }
                # Other errors - stop trying this feed
                throw
            }
        }

        if (-not $fetchSuccess -or $null -eq $webRequest) { continue }

        $content = [xml]$webRequest.Content
        
        $items = @()
        if ($content.rss.channel.item) {
            $items = $content.rss.channel.item
        } elseif ($content.feed.entry) {
            $items = $content.feed.entry
        } elseif ($content.rdf.item) {
            $items = $content.rdf.item
        }
        
        if ($items.Count -eq 0) {
            Write-Host " - No items found" -ForegroundColor DarkYellow
            continue
        }
        
        $MatchCount = 0
        $DuplicateCount = 0
        
        foreach ($item in $items) {
            $matchedKeywords = @()
            $fullText = Get-AllTextContent -Item $item
            
            if ([string]::IsNullOrWhiteSpace($fullText)) {
                continue
            }
            
            foreach ($keyword in $Keywords) {
                if ($fullText -match "(?i)\b$keyword\b") {
                    $matchedKeywords += $keyword
                }
            }
            
            if ($matchedKeywords.Count -gt 0) {
                $itemTitle = "Untitled"
                if ($item.title) {
                    if ($item.title -is [string]) {
                        $itemTitle = $item.title.ToString().Trim()
                    } elseif ($item.title.'#text') {
                        $itemTitle = $item.title.'#text'.ToString().Trim()
                    } else {
                        $itemTitle = $item.title.InnerText.Trim()
                    }
                }
                
                $itemLink = Get-ItemLink -Item $item -FeedUrl $url
                
                # Skip if link is null or empty
                if ([string]::IsNullOrWhiteSpace($itemLink)) {
                    continue
                }
                
                if ($ExistingLinks.ContainsKey($itemLink)) {
                    $DuplicateCount++
                    $DuplicatesSkipped++
                    continue
                }
                
                $MatchCount++
                $NewLinksCount++
                
                $itemDate = Get-Date
                if ($item.pubDate) {
                    try { $itemDate = [DateTime]$item.pubDate } catch { }
                } elseif ($item.published) {
                    try { $itemDate = [DateTime]$item.published } catch { }
                }
                
                $mitreTechniques = Get-MitreTechniques -Text $fullText
                $mitreString = if ($mitreTechniques.Count -gt 0) { $mitreTechniques -join "; " } else { "" }

                $Results.Add([PSCustomObject]@{
                    Date            = $itemDate
                    Source          = $url
                    Title           = $itemTitle
                    Keywords        = ($matchedKeywords | Sort-Object -Unique) -join ", "
                    MitreTechniques = $mitreString
                    Link            = $itemLink
                    IsNew           = $TrackNewLinks
                })
            }
        }
        
        if ($MatchCount -gt 0) {
            $statusMsg = " - Found $MatchCount new"
            if ($DuplicateCount -gt 0) {
                $statusMsg += " ($DuplicateCount duplicates skipped)"
            }
            Write-Host $statusMsg -ForegroundColor Green
        } else {
            Write-Host " - No matches" -ForegroundColor DarkGray
        }
    } catch { 
        Write-Host " - Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Scanning RSS Feeds" -Completed

Write-Host "`n[*] Processing results..." -ForegroundColor Cyan
Write-Host "New matches found: $NewLinksCount" -ForegroundColor Green
Write-Host "Duplicates skipped: $DuplicatesSkipped" -ForegroundColor Yellow

$AllResultsForCSV = @()

# First, add all NEW items found in this run
$UniqueResults = $Results | Sort-Object Link -Unique
foreach ($newItem in $UniqueResults) {
    $AllResultsForCSV += $newItem
}

# Then, add all PREVIOUS items from the old CSV (if loaded)
if ($PreviousCsvPath -and (Test-Path $PreviousCsvPath)) {
    $PreviousData = Import-Csv -Path $PreviousCsvPath -Encoding UTF8
    foreach ($prevItem in $PreviousData) {
        $AllResultsForCSV += [PSCustomObject]@{
            Date            = $prevItem.Date
            Source          = $prevItem.Source
            Title           = $prevItem.Title
            Keywords        = $prevItem.Keywords
            MitreTechniques = if ($prevItem.PSObject.Properties['MitreTechniques']) { $prevItem.MitreTechniques } else { "" }
            Link            = $prevItem.Link
            IsNew           = $false
        }
    }
}

# Sort ALL results by Date (newest first)
$AllResultsForCSV = $AllResultsForCSV | Sort-Object { 
    if ($_.Date -is [DateTime]) { 
        $_.Date 
    } else { 
        try { [DateTime]::Parse($_.Date) } catch { Get-Date -Year 2000 }
    }
} -Descending

# Export to CSV
$AllResultsForCSV | Select-Object Date, Source, Title, Keywords, MitreTechniques, Link | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# Statistics
$KeywordStats = @{}
foreach ($result in $AllResultsForCSV) {
    if ($result.Keywords) {
        $keywordList = $result.Keywords -split ',\s*'
        foreach ($kw in $keywordList) {
            $kw = $kw.Trim()
            if ($kw -ne "") {
                if ($KeywordStats.ContainsKey($kw)) {
                    $KeywordStats[$kw]++
                } else {
                    $KeywordStats[$kw] = 1
                }
            }
        }
    }
}

$MitreStats = @{}
foreach ($result in $AllResultsForCSV) {
    if ($result.MitreTechniques) {
        $techniqueList = $result.MitreTechniques -split ';\s*'
        foreach ($tech in $techniqueList) {
            $tech = $tech.Trim()
            if ($tech -ne "") {
                if ($MitreStats.ContainsKey($tech)) {
                    $MitreStats[$tech]++
                } else {
                    $MitreStats[$tech] = 1
                }
            }
        }
    }
}

# JavaScript data
$jsDataItems = New-Object System.Collections.ArrayList

foreach ($item in $AllResultsForCSV) {
    $itemDate = if ($item.Date -is [DateTime]) {
        $item.Date
    } else {
        try {
            [DateTime]::Parse($item.Date)
        } catch {
            Get-Date
        }
    }
    
    $dateStr = $itemDate.ToString("yyyy-MM-dd HH:mm")
    $timestamp = [Math]::Floor(([DateTimeOffset]$itemDate).ToUnixTimeSeconds())
    
    $jsTitle = $item.Title -replace '\\', '\\' -replace '"', '\"' -replace "`n", " " -replace "`r", ""
    $jsSource = $item.Source -replace '\\', '\\' -replace '"', '\"'
    $jsKeywords = $item.Keywords -replace '\\', '\\' -replace '"', '\"'
    $jsMitre = $item.MitreTechniques -replace '\\', '\\' -replace '"', '\"'
    $jsLink = $item.Link -replace '\\', '\\' -replace '"', '\"'
    $isNew = if ($item.IsNew) { "true" } else { "false" }

    $null = $jsDataItems.Add(@"
{ts:$timestamp,dt:"$dateStr",src:"$jsSource",ttl:"$jsTitle",kw:"$jsKeywords",mitre:"$jsMitre",lnk:"$jsLink",new:$isNew}
"@)
}

$jsArray = "[" + ($jsDataItems -join ",") + "]"

$jsKeywords = "{"
$first = $true
foreach ($kw in $KeywordStats.GetEnumerator()) {
    if (-not $first) { $jsKeywords += "," }
    $escapedKey = $kw.Key -replace '\\', '\\' -replace '"', '\"'
    $jsKeywords += "`"$escapedKey`":$($kw.Value)"
    $first = $false
}
$jsKeywords += "}"

$jsMitreStats = "{"
$first = $true
foreach ($tech in $MitreStats.GetEnumerator()) {
    if (-not $first) { $jsMitreStats += "," }
    $escapedKey = $tech.Key -replace '\\', '\\' -replace '"', '\"'
    $jsMitreStats += "`"$escapedKey`":$($tech.Value)"
    $first = $false
}
$jsMitreStats += "}"

Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan

$HtmlContent = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>APT Intelligence Report - MITRE ATT&CK</title>
<script src='https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js'></script>
<style>
:root{--bg:#f4f7f6;--txt:#333;--card:#fff;--head:#2c3e50;--accent:#3498db;--kwbg:#e8f4f8;--mitrebg:#fff3e0;--new-bg:#ff4757;--new-glow:rgba(255,71,87,0.3)}
[data-theme='dark']{--bg:#1a1a1a;--txt:#e0e0e0;--card:#2d2d2d;--head:#1a1a1a;--accent:#5dade2;--kwbg:#1e3a4a;--mitrebg:#3a2e1e;--new-bg:#ff6b81;--new-glow:rgba(255,107,129,0.4)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:var(--bg);color:var(--txt);transition:all .3s;line-height:1.6}
.palestine-banner{background:#000;color:#fff;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;font-size:14px;line-height:1.5;position:sticky;top:0;z-index:1000;box-shadow:0 2px 10px rgba(0,0,0,0.3)}
.palestine-banner-content{flex:1;display:flex;align-items:center;gap:10px}
.palestine-flag{font-size:24px}
.palestine-text{flex:1}
.palestine-text a{color:#2196F3;text-decoration:none;font-weight:bold;transition:color .2s}
.palestine-text a:hover{text-decoration:underline;color:#1976D2}
.banner-close{background:transparent;border:none;color:#fff;font-size:24px;cursor:pointer;padding:0 10px;line-height:1;transition:color .2s}
.banner-close:hover{color:#ff4757}
.wrap{margin:20px auto;max-width:1400px;padding:0 15px}
h2{margin:20px 0;font-size:24px}
.controls{display:flex;gap:15px;margin-bottom:25px;align-items:center;flex-wrap:wrap}
input[type='text'],select{padding:10px;border-radius:5px;border:1px solid #ccc;background:var(--card);color:var(--txt);font-size:14px;width:100%;max-width:300px}
select{min-width:160px;cursor:pointer}
.filter-group{display:flex;align-items:center;gap:8px;flex-wrap:nowrap}
.filter-label{font-weight:600;font-size:14px;white-space:nowrap}
.switch-container{display:flex;align-items:center;gap:8px;font-weight:bold}
.switch{position:relative;display:inline-block;width:50px;height:24px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#ccc;transition:.4s;border-radius:24px}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:4px;bottom:3px;background:#fff;transition:.4s;border-radius:50%}
input:checked+.slider{background:var(--accent)}
input:checked+.slider:before{transform:translateX(24px)}
.vuln-btn,.mitre-btn{background:linear-gradient(135deg,#e74c3c 0%,#c0392b 100%);color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;display:inline-flex;align-items:center;gap:8px;transition:all .3s;box-shadow:0 4px 15px rgba(231,76,60,0.3);white-space:nowrap}
.mitre-btn{background:linear-gradient(135deg,#ff9800 0%,#f57c00 100%);box-shadow:0 4px 15px rgba(255,152,0,0.3)}
.vuln-btn:hover{background:linear-gradient(135deg,#c0392b 0%,#a93226 100%);transform:translateY(-2px);box-shadow:0 6px 20px rgba(231,76,60,0.4)}
.mitre-btn:hover{background:linear-gradient(135deg,#f57c00 0%,#e65100 100%);transform:translateY(-2px);box-shadow:0 6px 20px rgba(255,152,0,0.4)}
.stats-info{margin-bottom:20px;padding:15px;background:var(--card);border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
.stats-info p{margin:5px 0;font-size:14px}
.stats-info strong{color:var(--accent)}
.chart-container{background:var(--card);padding:20px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);margin-bottom:25px;display:flex;align-items:center;gap:25px;flex-wrap:wrap}
.chart-wrapper{flex:0 0 180px;max-width:180px;height:180px}
.chart-legend{flex:1;min-width:220px}
.chart-legend h3{margin:0 0 15px 0;font-size:18px}
.legend-item{display:flex;align-items:center;margin-bottom:8px;font-size:13px;padding:6px;border-radius:5px;transition:background .2s}
.legend-item:hover{background:rgba(0,0,0,0.05)}
[data-theme='dark'] .legend-item:hover{background:rgba(255,255,255,0.05)}
.legend-color{width:18px;height:18px;border-radius:3px;margin-right:8px;flex-shrink:0}
.legend-text{flex:1;font-weight:500}
.legend-count{font-weight:600;margin-left:8px;color:var(--accent)}
.new-badge{display:inline-block;background:var(--new-bg);color:#fff;padding:3px 8px;border-radius:12px;font-size:10px;font-weight:bold;text-transform:uppercase;margin-left:8px;animation:pulse 2s infinite;box-shadow:0 0 10px var(--new-glow)}
@keyframes pulse{0%,100%{transform:scale(1);box-shadow:0 0 10px var(--new-glow)}50%{transform:scale(1.05);box-shadow:0 0 15px var(--new-glow)}}
.new-row{background:rgba(255,71,87,0.08)!important;border-left:4px solid var(--new-bg)!important}
[data-theme='dark'] .new-row{background:rgba(255,107,129,0.12)!important}
.mitre-badge{display:inline-block;background:#ff9800;color:#fff;padding:2px 6px;border-radius:4px;font-size:9px;font-weight:bold;margin:2px;white-space:nowrap}
.mitre-badge:hover{background:#f57c00;cursor:pointer}
.table-container{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;background:var(--card);box-shadow:0 2px 10px rgba(0,0,0,0.1);border-radius:8px;overflow:hidden;min-width:800px}
th,td{text-align:left;padding:12px;border-bottom:1px solid rgba(0,0,0,0.1);font-size:13px}
[data-theme='dark'] th,[data-theme='dark'] td{border-bottom:1px solid rgba(255,255,255,0.1)}
th{background:var(--head);color:#fff;font-weight:600;text-transform:uppercase;font-size:11px;white-space:nowrap}
tr{transition:all .2s}
tr:hover{background:rgba(0,0,0,0.03)}
[data-theme='dark'] tr:hover{background:rgba(255,255,255,0.03)}
tr:last-child td{border-bottom:none}
td:nth-child(4){background:var(--kwbg);font-weight:500;font-size:0.9em}
td:nth-child(5){background:var(--mitrebg);font-weight:500;font-size:0.85em}
a{color:var(--accent);text-decoration:none;font-weight:500;transition:color .2s;word-break:break-word}
a:hover{color:#2980b9;text-decoration:underline}
.article-link:visited{color:#9b59b6;opacity:0.7;text-decoration:line-through}
.link-cell{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
.article-link{font-size:14px;font-weight:600}
.ai-btns{display:flex;gap:5px;flex-wrap:wrap}
.ai-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;transition:all .2s;white-space:nowrap}
.ai-btn:hover{transform:translateY(-1px)}
.chatgpt-btn{background:linear-gradient(135deg,#10a37f 0%,#1a7f64 100%)}
.chatgpt-btn:hover{background:linear-gradient(135deg,#0d8c6d 0%,#148059 100%);box-shadow:0 2px 8px rgba(16,163,127,0.3)}
.claude-btn{background:linear-gradient(135deg,#DE7356 0%,#C15F3C 100%)}
.claude-btn:hover{background:linear-gradient(135deg,#C15F3C 0%,#A84D2E 100%);box-shadow:0 2px 8px rgba(193,95,60,0.3)}
.gemini-btn{background:linear-gradient(135deg,#4285f4 0%,#1a73e8 100%)}
.gemini-btn:hover{background:linear-gradient(135deg,#1a73e8 0%,#0d5bdd 100%);box-shadow:0 2px 8px rgba(66,133,244,0.3)}
.ai-icon{width:14px;height:14px;fill:currentColor}
.modal{display:none;position:fixed;z-index:2000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.7);animation:fadeIn .3s;overflow-y:auto}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal-content{background:var(--card);margin:2% auto;padding:0;width:95%;max-width:1200px;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:slideDown .3s;max-height:90vh;overflow-y:auto}
@keyframes slideDown{from{transform:translateY(-50px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-header{background:linear-gradient(135deg,#ff9800 0%,#f57c00 100%);color:#fff;padding:18px 25px;border-radius:12px 12px 0 0;display:flex;justify-content:space-between;align-items:center}
.modal-header h2{margin:0;font-size:20px}
.close-modal{color:#fff;font-size:28px;font-weight:bold;cursor:pointer;background:none;border:none;padding:0;width:36px;height:36px;display:flex;align-items:center;justify-content:center;border-radius:50%;transition:background .2s}
.close-modal:hover{background:rgba(255,255,255,0.2)}
.modal-body{padding:25px}
.mitre-chart{background:var(--card);padding:15px;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,0.1);margin-bottom:25px;height:280px}
.mitre-controls{display:flex;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.mitre-search{flex:1;min-width:220px;padding:10px;border-radius:8px;border:2px solid #ddd;font-size:13px;background:var(--card);color:var(--txt)}
.mitre-technique-card{background:var(--card);padding:15px;border-radius:8px;margin-bottom:15px;border-left:4px solid #ff9800;box-shadow:0 2px 8px rgba(0,0,0,0.1);transition:all .2s}
.mitre-technique-card:hover{box-shadow:0 4px 15px rgba(0,0,0,0.15);transform:translateX(5px)}
.mitre-technique-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.mitre-technique-id{font-weight:bold;color:#ff9800;font-size:14px}
.mitre-technique-name{font-weight:600;font-size:16px;margin-bottom:5px;color:var(--txt)}
.mitre-technique-count{background:#ff9800;color:#fff;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:bold}
.mitre-articles-list{margin-top:10px;padding-left:20px}
.mitre-article-item{font-size:13px;margin:5px 0;color:var(--txt)}
.mitre-article-link{color:var(--accent);text-decoration:none}
.mitre-article-link:hover{text-decoration:underline}
.see-more-btn{background:linear-gradient(135deg,#ff9800 0%,#f57c00 100%);color:#fff;border:none;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;transition:all .3s;box-shadow:0 2px 8px rgba(255,152,0,0.3)}
.see-more-btn:hover{background:linear-gradient(135deg,#f57c00 0%,#e65100 100%);transform:translateY(-2px);box-shadow:0 4px 12px rgba(255,152,0,0.4)}
.see-more-btn.expanded{background:linear-gradient(135deg,#2196f3 0%,#1976d2 100%)}
.see-more-btn.expanded:hover{background:linear-gradient(135deg,#1976d2 0%,#1565c0 100%)}
.mitre-articles-hidden{animation:slideDownArticles .3s ease-out}
@keyframes slideDownArticles{from{opacity:0;max-height:0}to{opacity:1;max-height:2000px}}
.vuln-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:15px;margin-bottom:25px}
.stat-card{background:linear-gradient(135deg,var(--card-bg) 0%,var(--card-bg-dark) 100%);padding:15px;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,0.1);border-left:5px solid var(--card-color);transition:transform .2s;cursor:pointer}
.stat-card:hover{transform:translateY(-5px)}
.stat-card.active{box-shadow:0 6px 25px rgba(0,0,0,0.2);border-left-width:8px}
.stat-card.critical{--card-bg:#fee;--card-bg-dark:#fdd;--card-color:#e74c3c}
.stat-card.high{--card-bg:#ffe8e0;--card-bg-dark:#ffd4c4;--card-color:#f39c12}
.stat-card.medium{--card-bg:#fff9e6;--card-bg-dark:#fff3cc;--card-color:#f1c40f}
.stat-card.low{--card-bg:#e8f8f5;--card-bg-dark:#d0f0e8;--card-color:#27ae60}
.stat-label{font-size:11px;text-transform:uppercase;font-weight:600;opacity:0.8;margin-bottom:5px}
.stat-value{font-size:32px;font-weight:bold;color:var(--card-color)}
.vuln-chart{background:var(--card);padding:15px;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,0.1);margin-bottom:25px;height:280px}
.vuln-controls{display:flex;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.vuln-search{flex:1;min-width:220px;padding:10px;border-radius:8px;border:2px solid #ddd;font-size:13px;background:var(--card);color:var(--txt)}
.vuln-table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;box-shadow:0 4px 15px rgba(0,0,0,0.1)}
.vuln-table th{background:var(--head);color:#fff;padding:12px;text-align:left;font-weight:600;text-transform:uppercase;font-size:11px}
.vuln-table td{padding:12px;border-bottom:1px solid rgba(0,0,0,0.1);font-size:13px}
[data-theme='dark'] .vuln-table td{border-bottom:1px solid rgba(255,255,255,0.1)}
.vuln-table tr:hover{background:rgba(0,0,0,0.03)}
[data-theme='dark'] .vuln-table tr:hover{background:rgba(255,255,255,0.03)}
.severity-badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:10px;font-weight:bold;text-transform:uppercase}
.severity-critical{background:#e74c3c;color:#fff}
.severity-high{background:#f39c12;color:#fff}
.severity-medium{background:#f1c40f;color:#333}
.severity-low{background:#27ae60;color:#fff}
.severity-unknown{background:#95a5a6;color:#fff}
.score-badge{display:inline-block;padding:4px 8px;border-radius:5px;font-weight:bold;background:var(--accent);color:#fff;font-size:12px}
.loading{text-align:center;padding:35px;font-size:16px}
.spinner{border:4px solid rgba(0,0,0,0.1);border-left-color:#e74c3c;border-radius:50%;width:36px;height:36px;animation:spin 1s linear infinite;margin:0 auto 18px}
@keyframes spin{to{transform:rotate(360deg)}}
.modal-header.vuln-header{background:linear-gradient(135deg,#e74c3c 0%,#c0392b 100%)}
</style>
</head>
<body>
<div class="palestine-banner" id="palestineBanner">
<div class="palestine-banner-content">
<span class="palestine-flag"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 90 60" width="40" height="27" style="display:inline-block;vertical-align:middle;border-radius:3px;box-shadow:0 1px 4px rgba(0,0,0,0.5);flex-shrink:0"><rect width="90" height="20" fill="#000000"/><rect y="20" width="90" height="20" fill="#FFFFFF"/><rect y="40" width="90" height="20" fill="#007A3D"/><polygon points="0,0 45,30 0,60" fill="#CE1126"/></svg></span>
<div class="palestine-text">
<strong><a href="https://www.palestinediasporamovement.com/palestine-101" target="_blank" style="color:#2196F3;text-decoration:none">#Free Palestine</a></strong> - Stand for humanity!
 Palestine has a right to defend itself. Together, we can put an end to the Gaza genocide. Let's unite to <a href="https://data.techforpalestine.org/" target="_blank">#SAVE GAZA</a> and ensure that every life in this region has access to the most basic necessities.
</div>
</div>
<button class="banner-close" onclick="closeBanner()" aria-label="Close banner">&#xD7;</button>
</div>
<div class="wrap">
<h2>&#x1F6E1;&#xFE0F; Threat Intelligence Report</h2>

<div class="stats-info">
<p><strong>Total Articles:</strong> <span id="totalCount">$($AllResultsForCSV.Count)</span></p>
<p><strong>New This Run:</strong> <span id="newCount" style="color:var(--new-bg);font-weight:bold">$NewLinksCount</span></p>
<p><strong>Displayed:</strong> <span id="displayedCount">$($AllResultsForCSV.Count)</span></p>
<p><strong>MITRE Techniques Detected:</strong> <span id="mitreCount" style="color:#ff9800;font-weight:bold">$($MitreStats.Count)</span></p>
<p><strong>Feeds Scanned:</strong> $TotalFeeds</p>
</div>

<div class='controls'>
<div class="filter-group">
<label class="filter-label">&#x1F4C5; Date:</label>
<select id="dateFilter" onchange="filterData()">
<option value="all">All Data</option>
<option value="1">Today</option>
<option value="7">Last Week</option>
<option value="30">Last Month</option>
<option value="90">Last 3 Months</option>    
<option value="180">Last 6 Months</option>
<option value="270">Last 9 Months</option>
<option value="365">Last Year</option>
</select>
</div>

<div class="filter-group">
<label class="filter-label">&#x2728; Status:</label>
<select id="statusFilter" onchange="filterData()">
<option value="all">All Articles</option>
<option value="new">New Only</option>
<option value="old">Old Only</option>
</select>
</div>

<button class="vuln-btn" onclick="openVulnModal()">
<span>&#x1F534;</span>
<span>Vulnerability Report</span>
</button>

<button class="mitre-btn" onclick="openMitreModal()">
<span>&#x2694;&#xFE0F;</span>
<span>MITRE ATT&CK</span>
</button>

<input type='text' id='searchInput' placeholder='Search for keywords, titles, or sources...' onkeyup='filterData()'>

<div class="switch-container">
<span>&#x2600;&#xFE0F;</span>
<label class="switch">
<input type="checkbox" id="themeToggle" onchange="toggleTheme()">
<span class="slider"></span>
</label>
<span>&#x1F319;</span>
</div>
</div>

<div class="chart-container">
<div class="chart-wrapper">
<canvas id="chart"></canvas>
</div>
<div class="chart-legend">
<h3>Keyword Distribution</h3>
<div id="legend"></div>
</div>
</div>

<div class="table-container">
<table>
<thead>
<tr><th>Date</th><th>Source</th><th>Title</th><th>Keywords</th><th>MITRE ATT&CK</th><th>Link</th></tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>
</div>

<div id="mitreModal" class="modal">
<div class="modal-content">
<div class="modal-header">
<h2>&#x2694;&#xFE0F; MITRE ATT&CK Techniques Detected</h2>
<button class="close-modal" onclick="closeMitreModal()">&#xD7;</button>
</div>
<div class="modal-body">
<div class="mitre-chart">
<canvas id="mitreChart"></canvas>
</div>
<div class="mitre-controls">
<input type="text" class="mitre-search" id="mitreSearch" placeholder="&#x1F50D; Search MITRE Technique..." onkeyup="filterMitreTechniques()">
</div>
<div id="mitreContent"></div>
</div>
</div>
</div>

<div id="vulnModal" class="modal">
<div class="modal-content">
<div class="modal-header vuln-header">
<h2>&#x1F534; Vulnerability Report (Last $VulnDays Days)</h2>
<button class="close-modal" onclick="closeVulnModal()">&#xD7;</button>
</div>
<div class="modal-body">
<div id="vulnLoading" class="loading">
<div class="spinner"></div>
<p>Loading CVE data from NVD...</p>
</div>
<div id="vulnContent" style="display:none">
<div class="vuln-stats">
<div class="stat-card critical" onclick="filterBySeverity('CRITICAL')">
<div class="stat-label">&#x1F534; Critical</div>
<div class="stat-value" id="criticalCount">0</div>
</div>
<div class="stat-card high" onclick="filterBySeverity('HIGH')">
<div class="stat-label">&#x1F7E0; High</div>
<div class="stat-value" id="highCount">0</div>
</div>
<div class="stat-card medium" onclick="filterBySeverity('MEDIUM')">
<div class="stat-label">&#x1F7E1; Medium</div>
<div class="stat-value" id="mediumCount">0</div>
</div>
<div class="stat-card low" onclick="filterBySeverity('LOW')">
<div class="stat-label">&#x1F7E2; Low</div>
<div class="stat-value" id="lowCount">0</div>
</div>
</div>
<div class="vuln-chart">
<canvas id="vulnChart"></canvas>
</div>
<div class="vuln-controls">
<input type="text" class="vuln-search" id="vulnSearch" placeholder="&#x1F50D; Search CVE ID or Description..." onkeyup="filterVulnTable()">
</div>
<div class="table-container">
<table class="vuln-table">
<thead>
<tr><th>CVE ID</th><th>Published Date</th><th>Severity</th><th>CVSS Score</th><th>Description</th></tr>
</thead>
<tbody id="vulnTableBody"></tbody>
</table>
</div>
</div>
</div>
</div>
</div>

<script>
const allData=$jsArray;
const keywordData=$jsKeywords;
const mitreData=$jsMitreStats;
let chart=null;
let mitreChart=null;
let vulnChart=null;
let allVulnData=[];
let filteredVulnData=[];
let activeSeverityFilter='ALL';
const colors=['#FF6384','#36A2EB','#FFCE56','#4BC0C0','#9966FF','#FF9F40','#E7E9ED','#8BC34A','#FF5722','#795548'];
const VULN_DAYS=$VulnDays;

function toggleTheme(){
const dark=document.getElementById('themeToggle').checked;
document.documentElement.setAttribute('data-theme',dark?'dark':'light');
localStorage.setItem('theme',dark?'dark':'light');
}

function loadTheme(){
const savedTheme=localStorage.getItem('theme');
if(savedTheme==='dark'){
document.documentElement.setAttribute('data-theme','dark');
document.getElementById('themeToggle').checked=true;
}
}

function getDaysAgo(days){
return Math.floor(Date.now()/1000)-(days*86400);
}

function filterData(){
const search=document.getElementById('searchInput').value.toUpperCase();
const dateVal=document.getElementById('dateFilter').value;
const statusVal=document.getElementById('statusFilter').value;
const cutoff=dateVal==='all'?0:getDaysAgo(parseInt(dateVal));

let displayed=0;
let kwCount={};
const tbody=document.getElementById('tableBody');
tbody.innerHTML='';

allData.forEach(item=>{
const matchSearch=!search||(item.ttl.toUpperCase().includes(search)||item.src.toUpperCase().includes(search)||item.kw.toUpperCase().includes(search)||item.mitre.toUpperCase().includes(search));
const matchDate=dateVal==='all'||item.ts>=cutoff;
const matchStatus=statusVal==='all'||(statusVal==='new'&&item.new)||(statusVal==='old'&&!item.new);

if(matchSearch&&matchDate&&matchStatus){
displayed++;
item.kw.split(',').forEach(k=>{
k=k.trim();
if(k)kwCount[k]=(kwCount[k]||0)+1;
});

const row=tbody.insertRow();
if(item.new){
row.className='new-row';
}

const escapedLink=item.lnk.replace(/'/g,"\\\\'").replace(/"/g,'&quot;');
const escapedTitle=item.ttl.replace(/'/g,"\\\\'").replace(/"/g,'&quot;');
const linkWithBadge=item.new?'<a href="'+item.lnk+'" target="_blank" class="article-link">View Article</a><span class="new-badge" style="margin-left:5px">NEW</span>':'<a href="'+item.lnk+'" target="_blank" class="article-link">View Article</a>';
const mitreBadges=item.mitre?item.mitre.split(';').map(m=>'<span class="mitre-badge" onclick="searchMitre(\''+m.trim().split(' ')[0]+'\')">'+m.trim()+'</span>').join(''):'';

row.innerHTML='<td>'+item.dt+'</td><td>'+item.src+'</td><td>'+item.ttl+(item.new?'<span class="new-badge">NEW</span>':'')+'</td><td>'+item.kw+'</td><td>'+mitreBadges+'</td><td><div class="link-cell">'+linkWithBadge+'<div class="ai-btns"><button class="ai-btn chatgpt-btn" onclick="openChatGPT(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg class="ai-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M22.3 8.7c.2-.5.3-1 .3-1.5 0-1.7-.9-3.3-2.4-4.2-.8-.5-1.7-.8-2.6-.8-1 0-1.9.3-2.7.9-.8.6-1.4 1.4-1.7 2.3-.7.1-1.3.4-1.9.8-.6.4-1 1-1.3 1.6-.5.9-.7 1.9-.5 2.9.1 1 .6 1.9 1.3 2.6-.2.5-.3 1-.3 1.6 0 1.7.9 3.3 2.4 4.2.8.5 1.7.8 2.6.8 1 0 1.9-.3 2.7-.9.8-.6 1.4-1.4 1.7-2.3.7-.1 1.3-.4 1.9-.8.6-.4 1-1 1.3-1.6.5-.9.7-1.9.5-2.9-.1-1-.6-1.9-1.3-2.6z"/></svg>ChatGPT</button><button class="ai-btn claude-btn" onclick="openClaude(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg class="ai-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M17.5 3L7 8.5v7L17.5 21l10.5-5.5v-7L17.5 3z"/></svg>Claude</button><button class="ai-btn gemini-btn" onclick="openGemini(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg class="ai-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2L2 7v10l10 5 10-5V7L12 2z"/></svg>Gemini</button></div></div></td>';
}
});

document.getElementById('displayedCount').textContent=displayed;
updateChart(kwCount);
}

function updateChart(kwCount){
const sortedKw=Object.entries(kwCount).sort((a,b)=>b[1]-a[1]).slice(0,10);
const labels=sortedKw.map(x=>x[0]);
const data=sortedKw.map(x=>x[1]);
const bgColors=sortedKw.map((x,i)=>colors[i%colors.length]);

const legendDiv=document.getElementById('legend');
legendDiv.innerHTML='';
sortedKw.forEach((kw,i)=>{
const item=document.createElement('div');
item.className='legend-item';
item.innerHTML='<div class="legend-color" style="background:'+bgColors[i]+'"></div><span class="legend-text">'+kw[0]+'</span><span class="legend-count">'+kw[1]+'</span>';
legendDiv.appendChild(item);
});

if(chart)chart.destroy();
const ctx=document.getElementById('chart').getContext('2d');
chart=new Chart(ctx,{
type:'doughnut',
data:{labels:labels,datasets:[{data:data,backgroundColor:bgColors,borderWidth:2,borderColor:getComputedStyle(document.documentElement).getPropertyValue('--card')}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}}
});
}

function openMitreModal(){
document.getElementById('mitreModal').style.display='block';
renderMitreTechniques();
updateMitreChart();
}

function closeMitreModal(){
document.getElementById('mitreModal').style.display='none';
}

function renderMitreTechniques(){
const mitreContent=document.getElementById('mitreContent');
mitreContent.innerHTML='';

const mitreMap={};
allData.forEach(item=>{
if(item.mitre){
item.mitre.split(';').forEach(tech=>{
const techTrim=tech.trim();
if(techTrim){
if(!mitreMap[techTrim]){
mitreMap[techTrim]={count:0,articles:[]};
}
mitreMap[techTrim].count++;
mitreMap[techTrim].articles.push({title:item.ttl,link:item.lnk,date:item.dt});
}
});
}
});

const sortedTechs=Object.entries(mitreMap).sort((a,b)=>b[1].count-a[1].count);

sortedTechs.forEach(([tech,data],index)=>{
const parts=tech.split(' - ');
const techId=parts[0];
const techName=parts.slice(1).join(' - ');

const initialShow = 5;
const hasMore = data.articles.length > initialShow;
const articlesToShow = hasMore ? data.articles.slice(0, initialShow) : data.articles;
const remainingCount = data.articles.length - initialShow;

const card=document.createElement('div');
card.className='mitre-technique-card';

let html = '';
html += '<div class="mitre-technique-header">';
html += '<div>';
html += '<div class="mitre-technique-id">'+techId+'</div>';
html += '<div class="mitre-technique-name">'+techName+'</div>';
html += '</div>';
html += '<div class="mitre-technique-count">'+data.count+' article'+(data.count>1?'s':'')+'</div>';
html += '</div>';

html += '<div class="mitre-articles-list" id="mitre-list-'+index+'">';
articlesToShow.forEach(art=>{
html += '<div class="mitre-article-item">\u2022 <a href="'+art.link+'" target="_blank" class="mitre-article-link">'+art.title+'</a> <span style="color:#999;font-size:11px">('+art.date+')</span></div>';
});
html += '</div>';

if(hasMore){
html += '<div style="text-align:center;margin-top:10px">';
html += '<button class="see-more-btn" onclick="toggleMitreArticles('+index+', '+data.articles.length+')" id="toggle-btn-'+index+'">';
html += '\u25BC See More ('+remainingCount+' more)';
html += '</button>';
html += '</div>';

html += '<div class="mitre-articles-list mitre-articles-hidden" id="mitre-list-extra-'+index+'" style="display:none">';
data.articles.slice(initialShow).forEach(art=>{
html += '<div class="mitre-article-item">\u2022 <a href="'+art.link+'" target="_blank" class="mitre-article-link">'+art.title+'</a> <span style="color:#999;font-size:11px">('+art.date+')</span></div>';
});
html += '</div>';
}

card.innerHTML = html;
mitreContent.appendChild(card);
});
}

function toggleMitreArticles(index, totalCount){
const extraList = document.getElementById('mitre-list-extra-' + index);
const toggleBtn = document.getElementById('toggle-btn-' + index);

if(extraList.style.display === 'none'){
extraList.style.display = 'block';
toggleBtn.innerHTML = '\u25B2 See Less';
toggleBtn.classList.add('expanded');
} else {
extraList.style.display = 'none';
const remainingCount = totalCount - 5;
toggleBtn.innerHTML = '\u25BC See More (' + remainingCount + ' more)';
toggleBtn.classList.remove('expanded');
}
}

function updateMitreChart(){
const sortedMitre=Object.entries(mitreData).sort((a,b)=>b[1]-a[1]).slice(0,10);
const labels=sortedMitre.map(x=>x[0].split(' - ')[0]);
const data=sortedMitre.map(x=>x[1]);
const bgColors=['#065f46','#047857','#059669','#10b981','#34d399','#6ee7b7','#a7f3d0','#d1fae5','#ecfdf5','#f0fdf4'];

if(mitreChart)mitreChart.destroy();
const ctx=document.getElementById('mitreChart').getContext('2d');
mitreChart=new Chart(ctx,{
type:'bar',
data:{labels:labels,datasets:[{label:'Occurrences',data:data,backgroundColor:bgColors,borderWidth:0}]},
options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{precision:0}}}}
});
}

function filterMitreTechniques(){
const search=document.getElementById('mitreSearch').value.toUpperCase();
const cards=document.querySelectorAll('.mitre-technique-card');
cards.forEach(card=>{
const text=card.textContent.toUpperCase();
card.style.display=text.includes(search)?'block':'none';
});
}

function searchMitre(techniqueId){
openMitreModal();
setTimeout(()=>{
document.getElementById('mitreSearch').value=techniqueId;
filterMitreTechniques();
},100);
}

function openChatGPT(url,title){
window.open('https://chatgpt.com/?q='+encodeURIComponent('Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations. Article URL: '+url),'_blank');
}

function openClaude(url,title){
window.open('https://claude.ai/new?q='+encodeURIComponent('Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations. Article URL: '+url),'_blank');
}

function openGemini(url,title){
const prompt='Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations. Article URL: '+url;
navigator.clipboard.writeText(prompt).then(()=>{
window.open('https://gemini.google.com/app','_blank');
alert('Prompt copied to clipboard! Paste it in Gemini (Ctrl+V or Cmd+V).');
}).catch(()=>{
window.open('https://gemini.google.com/app','_blank');
alert('Please manually paste: Summarize this article: '+url);
});
}

async function openVulnModal(){
document.getElementById('vulnModal').style.display='block';
document.getElementById('vulnLoading').style.display='block';
document.getElementById('vulnContent').style.display='none';
activeSeverityFilter='ALL';
await fetchVulnerabilities();
}

function closeVulnModal(){
document.getElementById('vulnModal').style.display='none';
}

async function fetchVulnerabilities(){
try{
const endDate=new Date();
const startDate=new Date();
startDate.setDate(startDate.getDate()-VULN_DAYS);

const startStr=startDate.toISOString().split('T')[0]+'T00:00:00.000';
const endStr=endDate.toISOString().split('T')[0]+'T23:59:59.999';

const url='https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate='+startStr+'&pubEndDate='+endStr;

const response=await fetch(url);
const data=await response.json();

if(data.vulnerabilities){
allVulnData=data.vulnerabilities.map(v=>{
const cve=v.cve;
const metrics=cve.metrics;
let severity='UNKNOWN';
let score=0;

if(metrics?.cvssMetricV31&&metrics.cvssMetricV31.length>0){
severity=metrics.cvssMetricV31[0].cvssData.baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV31[0].cvssData.baseScore||0;
}else if(metrics?.cvssMetricV3&&metrics.cvssMetricV3.length>0){
severity=metrics.cvssMetricV3[0].cvssData.baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV3[0].cvssData.baseScore||0;
}else if(metrics?.cvssMetricV2&&metrics.cvssMetricV2.length>0){
severity=metrics.cvssMetricV2[0].baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV2[0].cvssData.baseScore||0;
}

const desc=cve.descriptions?.find(d=>d.lang==='en')?.value||'No description available';

return{
id:cve.id,
published:new Date(cve.published),
severity:severity,
score:score,
description:desc
};
});

filteredVulnData=[...allVulnData];
displayVulnData();
}else{
document.getElementById('vulnLoading').innerHTML='<p>No vulnerabilities found.</p>';
}
}catch(err){
document.getElementById('vulnLoading').innerHTML='<p style="color:red">Error loading data: '+err.message+'</p>';
}
}

function displayVulnData(){
document.getElementById('vulnLoading').style.display='none';
document.getElementById('vulnContent').style.display='block';

const stats={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
filteredVulnData.forEach(v=>{
if(stats.hasOwnProperty(v.severity))stats[v.severity]++;
});

document.getElementById('criticalCount').textContent=stats.CRITICAL;
document.getElementById('highCount').textContent=stats.HIGH;
document.getElementById('mediumCount').textContent=stats.MEDIUM;
document.getElementById('lowCount').textContent=stats.LOW;

updateVulnChart(stats);
renderVulnTable();
}

function updateVulnChart(stats){
const labels=['Critical','High','Medium','Low'];
const data=[stats.CRITICAL,stats.HIGH,stats.MEDIUM,stats.LOW];
const bgColors=['#e74c3c','#f39c12','#f1c40f','#27ae60'];

if(vulnChart)vulnChart.destroy();
const ctx=document.getElementById('vulnChart').getContext('2d');
vulnChart=new Chart(ctx,{
type:'bar',
data:{labels:labels,datasets:[{label:'Vulnerabilities',data:data,backgroundColor:bgColors,borderWidth:0}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0}}}}
});
}

function escapeHtml(text){
const div=document.createElement('div');
div.appendChild(document.createTextNode(String(text)));
return div.innerHTML;
}

function renderVulnTable(){
const tbody=document.getElementById('vulnTableBody');
tbody.innerHTML='';

const sortedData=[...filteredVulnData].sort((a,b)=>b.published-a.published);

sortedData.forEach(v=>{
const row=tbody.insertRow();
const dateStr=v.published.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
const sevClass='severity-'+v.severity.toLowerCase();
const cveUrl='https://nvd.nist.gov/vuln/detail/'+escapeHtml(v.id);
const displaySeverity=v.severity==='UNKNOWN'?'NVD assessment not yet provided.':escapeHtml(v.severity);
const scoreDisplay=v.score>0?'<span class="score-badge">'+v.score.toFixed(1)+'</span>':'<span style="color:#999">N/A</span>';
row.innerHTML='<td><a href="'+cveUrl+'" target="_blank" style="font-weight:bold;color:var(--accent)">'+escapeHtml(v.id)+'</a></td><td>'+escapeHtml(dateStr)+'</td><td><span class="severity-badge '+sevClass+'">'+displaySeverity+'</span></td><td>'+scoreDisplay+'</td><td>'+escapeHtml(v.description)+'</td>';
});
}

function filterBySeverity(severity){
document.querySelectorAll('.stat-card').forEach(c=>c.classList.remove('active'));
if(activeSeverityFilter===severity){
activeSeverityFilter='ALL';
filteredVulnData=[...allVulnData];
}else{
activeSeverityFilter=severity;
filteredVulnData=allVulnData.filter(v=>v.severity===severity);
event.currentTarget.classList.add('active');
}
displayVulnData();
}

function filterVulnTable(){
const search=document.getElementById('vulnSearch').value.toUpperCase();
if(!search){
filteredVulnData=activeSeverityFilter==='ALL'?[...allVulnData]:allVulnData.filter(v=>v.severity===activeSeverityFilter);
}else{
const baseData=activeSeverityFilter==='ALL'?allVulnData:allVulnData.filter(v=>v.severity===activeSeverityFilter);
filteredVulnData=baseData.filter(v=>v.id.toUpperCase().includes(search)||v.description.toUpperCase().includes(search));
}
renderVulnTable();
}

window.onclick=function(event){
if(event.target==document.getElementById('mitreModal')){
closeMitreModal();
}
if(event.target==document.getElementById('vulnModal')){
closeVulnModal();
}
}

function closeBanner(){
document.getElementById('palestineBanner').style.display='none';
}

window.onload=()=>{
loadTheme();
filterData();
document.getElementById('totalCount').textContent=allData.length;
const newItemsCount=allData.filter(x=>x.new).length;
document.getElementById('newCount').textContent=newItemsCount;
document.getElementById('mitreCount').textContent=Object.keys(mitreData).length;
};
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($HtmlPath, $HtmlContent, [System.Text.UTF8Encoding]::new($false))

Write-Host "`n[✓] Report generated successfully!" -ForegroundColor Green
Write-Host "CSV: $CsvPath" -ForegroundColor Cyan
Write-Host "HTML: $HtmlPath" -ForegroundColor Cyan
Write-Host "`n📊 Summary:" -ForegroundColor Yellow
Write-Host "  New links found: $NewLinksCount" -ForegroundColor Green
Write-Host "  Duplicates skipped: $DuplicatesSkipped" -ForegroundColor Yellow
Write-Host "  Total in report: $($AllResultsForCSV.Count)" -ForegroundColor Cyan
Write-Host "  MITRE Techniques: $($MitreStats.Count)" -ForegroundColor Magenta
Write-Host "`nOpening HTML report..." -ForegroundColor Yellow
Start-Process $HtmlPath
