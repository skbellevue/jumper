# A simple password hash REST API written in go

## Prerequisites
To run this code, you must install Go Tools.
Instructions​ are available at https://golang.org/doc/install
I recommend Visual Studio Code to run and debug. VS Code can be downloaded at https://code.visualstudio.com/


## Running the code
- Checkout this repository. Make sure your GOPATH is properly set. Instructions can be found at https://golang.org/doc/install
- Using the command line (macOS Terminal, Linux terminal, or cmd on Windows), navigate to the project root and type `go run jumper.go`
- You can now use your favorite client to consume the REST API. I recommend Postman, or simply curl. The server listen on port `8080`

## Testing the code
- Navigate to the project root
- Type `go test`

The test method will run tests against all the endpoints described below.

## Debugging using VS Code
Using Visual Studio Code, open the root folder to view the project.
I have included a launch.json file. Just use the debugger and run the configuration named `Launch File`.
You can then set breakpoints and perform step by step debugging, view your variables, etc.


## The REST API
### Requesting a hash
`POST /hash`
<br />
**Example:** `curl -X —data “password=angryMonkey” http://localhost:8080/hash`
#####  Discussion
If the request succeeds, then you get a `202` status code, and the `Location` header will point to the url to obtain the formal hashed password (Example: `/hash/1`).
The response body is a JSON structure with a single field, e.g `{"Id" : 1}`.
You can query the formal hash using that Id

### Getting the hashed string
`GET /hash/:id`
<br />
**Example:** `curl http://localhost:8080/hash/12` 
#####  Discussion
If the initial request is not fulflled yet, then this call will return a `202` status code.
If the `id` is not a valid identifier, then this call will return `404 Not Found`.
If the initial request is fulfilled, then you get a `200` status code, and the response body is a plain text that represents the base64 encoded hash.

### Statistics
`GET /stats`
<br />

**Example:** `curl http://localhost:8080/stats` 

#####  Discussion
Returns basic statistics about the hash requests.
The response body is a json structure. Example: `{ "total: 156, "average": 500324 }`