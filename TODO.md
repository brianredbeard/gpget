
## TODO
Below is a rough list of things to be resolved

### Functionality
  * Improve in memory handling (Fixes [Issue 4](gpget#4))
  * Improve filename handling
  * Support Trust levels
  * Document exit codes and make them more explicit
  * Show the progress of a current download (Fixes [Issue 2](gpget#2))

### Bugs
  * Don't use  ioutil.ReadAll() when reading the HTTP content. Instead use an io.Reader() (Fixes [Issue 4](gpget#4))

### Vulnerabilities
None reported
