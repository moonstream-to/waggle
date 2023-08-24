package waggle

func ExampleServer_PingRoute() {
	// Example of request and response from PingRoute

	// Output:
	// # Request
	// GET /ping HTTP/1.1
	//
	// # Response
	// HTTP/1.1 200 OK
	//
	// {
	//   "status": "ok"
	// }
}

func ExampleServer_SignDropperRoute() {
	// Example of request and response from SignDropperRoute

	// Output:
	// # Request
	// POST /sign/dropper HTTP/1.1
	// Content-Type: application/json
	//
	// {
	// 	"chain_id": 80001,
	// 	"dropper": "0x4ec36E288E1b5d6914851a141cb041152Cf95328",
	// 	"signer": "0x629c51488a18fc75f4b8993743f3c132316951c9",
	// 	"requests": [
	// 		{
	// 			"dropId": "2",
	// 			"requestID": "5",
	// 			"claimant": "0x000000000000000000000000000000000000dEaD",
	// 			"blockDeadline": "40000000",
	// 			"amount": "3000000000000000000"
	// 		},
	// 		{
	// 			"dropId": "2",
	// 			"requestID": "6",
	// 			"claimant": "0x000000000000000000000000000000000000dEaD",
	// 			"blockDeadline": "40000000",
	// 			"amount": "3000000000000000000"
	// 		}
	// 	]
	// }
	//
	// # Response
	// HTTP/1.1 200 OK
	// Content-Type: application/json
	//
	// {
	// 	"chain_id": 80001,
	// 	"dropper": "0x4ec36E288E1b5d6914851a141cb041152Cf95328",
	// 	"signer": "0x629c51488a18fc75f4b8993743f3c132316951c9",
	// 	"sensible": false,
	// 	"requests": [
	// 		{
	// 			"dropId": "2",
	// 			"requestID": "5",
	// 			"claimant": "0x000000000000000000000000000000000000dEaD",
	// 			"blockDeadline": "40000000",
	// 			"amount": "3000000000000000000",
	// 			"signature": "8165f3e1edba760f570c833891ef238c9e40d3e2d1c6d66ab39904d1934c4bb9642e463bd24e0464cceb16a91ea96a48965bb7603d59dc6b859f1112d077a5e61b",
	// 			"signer": "0x629c51488a18fc75f4b8993743f3c132316951c9"
	// 		},
	// 		{
	// 			"dropId": "2",
	// 			"requestID": "6",
	// 			"claimant": "0x000000000000000000000000000000000000dEaD",
	// 			"blockDeadline": "40000000",
	// 			"amount": "3000000000000000000",
	// 			"signature": "85177edfac02da74776e761f230dc8d1c367ec3fb400881224d8e6001b00b17326048930b0b6e4a03ce407933e12399f80b325cc0be075fad855a3c6168f3b221c",
	// 			"signer": "0x629c51488a18fc75f4b8993743f3c132316951c9"
	// 		}
	// 	]
	// }
}
