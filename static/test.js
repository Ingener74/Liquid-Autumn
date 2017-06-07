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