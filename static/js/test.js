$("#quitBtn").click(function () {
    $.get("quit", function (data) {
    })
});

$("#selectGame1Btn").click(function () {
    $.get("test_json", function (data, status) {
        console.log("answer " + data.test);
        $("#selectGame1Result").html("Result: " + data.test);
    })
});

$("#makePost").click(function () {
    $.post("test_post", JSON.stringify({
        "test": 3.1415,
        "e": 2.72,
        "firstName": "Pasha",
        "lastName": "Shnaider"
    })).done(function (data, status) {
        console.log("answer");
    })
});

$("#makeGet").click(function () {
    $.get("test_get", {
        "city": "Moscow",
        "street": "Proizvodstvennaya"
    }).done(function (data, status) {
        console.log("get answer");
    })
});

// setInterval(function () {
//     $.get("update_log", function (data, status) {
//         $("#log").html(data.log)
//     })
//
// }, 1000);
