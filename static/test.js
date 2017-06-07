function onButtonClick() {
    console.log("on button click");
    $.get("test_json", function (data, status) {
        console.log("on button click and get response");
        console.log(data.test);
    })
}

$("#select_game_1").click(function () {
    alert("on select game 1");
});

function onGameSelect1Click() {
    alert("on select game 1");
}