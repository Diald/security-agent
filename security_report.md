# Security Report

**Status:** 170

**Risk Score:** 170

## Findings

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Starting a process with a shell, possible injection detected, security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/commands/edit.py
- **Lines:** 48

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Starting a process with a shell, possible injection detected, security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/commands/genspider.py
- **Lines:** 123

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** medium
- **Message:** Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/core/downloader/contextfactory.py
- **Lines:** 49

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** medium
- **Message:** Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/core/downloader/contextfactory.py
- **Lines:** 75

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** high
- **Message:** Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/extensions/httpcache.py
- **Lines:** 307

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** high
- **Message:** Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/extensions/httpcache.py
- **Lines:** 389

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** high
- **Message:** Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/extensions/spiderstate.py
- **Lines:** 44

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Using xmlrpc.client to parse untrusted XML data is known to be vulnerable to XML attacks. Use defusedxml.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/http/request/rpc.py
- **Lines:** 10

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/files.py
- **Lines:** 18

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak MD5 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/files.py
- **Lines:** 68

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/files.py
- **Lines:** 402

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak MD5 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/files.py
- **Lines:** 409

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak SHA1 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/files.py
- **Lines:** 726

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak SHA1 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/images.py
- **Lines:** 248

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak SHA1 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pipelines/images.py
- **Lines:** 260

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak MD5 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/pqueues.py
- **Lines:** 36

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** high
- **Message:** Use of possibly insecure function - consider using safer ast.literal_eval.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/shell.py
- **Lines:** 81

### [SAST] Finding
 - **Source:** bandit
- **Severity:** medium
- **Confidence:** high
- **Message:** Use of possibly insecure function - consider using safer ast.literal_eval.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/engine.py
- **Lines:** 35

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/ftp.py
- **Lines:** 2

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/ftp.py
- **Lines:** 35

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak MD5 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/misc.py
- **Lines:** 154

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** Use of weak SHA1 hash for security. Consider usedforsecurity=False
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/request.py
- **Lines:** 94

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/test.py
- **Lines:** 10

### [SAST] Finding
 - **Source:** bandit
- **Severity:** high
- **Confidence:** high
- **Message:** FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
- **File:** C:/Users/divya/Downloads/open-source1/scrapy/scrapy/utils/test.py
- **Lines:** 94
