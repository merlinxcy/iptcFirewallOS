/**
 * Created by wufei on 2016/11/10.
 */
sysStatus();
function displayStatus(arr) {
    var node0=document.createElement("p");
    node0.textContent=arr[0];
    node0.className="statusTitle";
    var nodeMAC=document.createElement("p");
    nodeMAC.textContent="MAC地址"+arr[1].AF_PACKET[0].addr;
    if (arr[1].AF_INET){
        var broadcast=arr[1].AF_INET[0].broadcast;
        if(broadcast){
            var nodeBC=document.createElement("p")
            nodeBC.textContent="广播地址"+broadcast;
        }
        var nodeMSK=document.createElement("p");
        nodeMSK.textContent="子网掩码"+arr[1].AF_INET[0].netmask;
        var nodeIP=document.createElement("p");
        nodeIP.textContent="IP地址"+arr[1].AF_INET[0].addr;
    }
    $("#sysStatus").append(node0,nodeMAC,nodeBC,nodeMSK,nodeIP);
}
function sysStatus() {
    $.ajax({
        url: "/system_status",
        type: "GET",
        complete:function (e,xhr,settings) {
            if(e.status===401){
                console.log("登陆已超时")
            }else if(e.status===200||e.status===304){
                var data=eval("("+e.responseText+")");
                var info=[];var j=0;
                for(var i in data){
                    info[j]=[];
                    info[j][0]=i;info[j][1]=data[i];
                    j++;
                }
                for(var m=0;m<info.length;m++){
                    displayStatus(info[m]);
                }
            }else{
                console.log("服务器请求失败")
            }
        }
    })
}
function fwRules() {
    $.ajax({
        url:"/firewall/display",
        type:"GET",
        complete:function (e,xhr,settings) {
            if(e.status===401){
                console.log("未登陆");
            }else if(e.status===200||e.status===304){
                displayRules(eval("("+e.responseText+")"));
                delBtn($(".del>button"));
            }else{
                console.log("服务器请求失败")
            }
        }
    })
}
function displayRules(data) {
    var inputRules = data.rules[0].INPUT;
    // console.log(inputRules);
    var outputRules = data.rules[1].OUTPUT;
    var forwardRules = data.rules[2].FORWARD;
    for (var i = 0; i < inputRules.length;i++) {
        $("#inputChain").append("<tr id='INPUT"+inputRules[i].number+"' class='rules'></tr>");
        sortRules(inputRules[i],$("#INPUT"+inputRules[i].number));
    };
    for (var i = 0; i < outputRules.length;i++) {
        $("#outputChain").append("<tr id='OUTPUT"+outputRules[i].number+"' class='rules'></tr>");
        sortRules(outputRules[i],$("#OUTPUT"+outputRules[i].number));
    };
    for (var i = 0; i < forwardRules.length;i++) {
        $("#forwardChain").append("<tr id='FORWARD"+forwardRules[i].number+"' class='rules'></tr>");
        sortRules(forwardRules[i],$("#FORWARD"+forwardRules[i].number));
    };
}
function sortRules(rules,father) {
    father.append("<td>"+rules.protocol+"</td>");
    father.append("<td>"+rules.src+"</td>");
    father.append("<td>"+rules.sport+"</td>");
    father.append("<td>"+rules.dst+"</td>");
    father.append("<td>"+rules.dport+"</td>");
    father.append("<td>"+rules.in+"</td>");
    father.append("<td>"+rules.out+"</td>");
    father.append("<td>"+rules.action+"</td>");
    father.append("<td class='del'><button></button></td>")
}
// var test='{"rules":[{"INPUT":[{"src":"192.168.1.1/255.255.255.255","protocol":"tcp","dst":"0.0.0.0/0.0.0.0","number":0,"dport":"50","in":null,"action":"ACCEPT","sport":"","out":null},{"src":"192.168.1.1/255.255.255.255","protocol":"tcp","dst":"0.0.0.0/0.0.0.0","number":2,"dport":"50","in":null,"action":"ACCEPT","sport":"","out":null}]},{"OUTPUT":[{"src":"192.168.1.1/255.255.255.255","protocol":"tcp","dst":"0.0.0.0/0.0.0.0","number":3,"dport":"50","in":null,"action":"ACCEPT","sport":"","out":null}]},{"FORWARD":[{"src":"192.168.1.1/255.255.255.255","protocol":"tcp","dst":"0.0.0.0/0.0.0.0","number":4,"dport":"50","in":null,"action":"ACCEPT","sport":"","out":null}]}],"result":"True"}';
// var test1=eval("("+test+")");
// console.log(test1);
// displayRules(test1);
function delBtn(btn) {
    btn.mouseover(function () {
        $(this).css("background-color","#E10000")
    });    
    btn.mousedown(function () {
        $(this).css("background-color","#C00000")
    });    
    btn.mouseup(function () {
        $(this).css("background-color","#F00")
    });    
    btn.mouseout(function () {
        $(this).css("background-color","#F00")
    });
    btn.click(function () {
        delId=$(this). parent().parent().attr("id");
        $("#delConfirm").css("display","block");
    });
}
$("#delConfirmFalse").click(function () {
    $("#delConfirm").css("display","none");
});
var delId;
$("#delConfirmTrue").click(function () {
    delAjax(delId);
});

function delAjax(delId) {
    $.ajax({
        url: "/firewall/delete",
        type: "POST",
        data: '{"chain":"'+delId.match(/[A-Z]+/)[0]+'","number":"'+delId.match(/[0-9]+/)[0]+'"}',
        complete: function(e,xhr,settings) {
            if(e.status===401){
                console.log("登陆已超时")
            }else if(e.status===406){
                console.log("数据格式异常");
            }else if(e.status===200){
                var info=eval("("+e.responseText+")");
                if(info.result=="True"){
                    $("#delConfirm").css("display","none");
                    $("#firewallRules tr.rules").remove();
                    fwRules();
                }else {
                    $("#delError").text(info.error_message);
                }
            }else{
                console.log("服务器请求失败");
            }
        }
    });
}
$("#addRulesBtn").click(function () {
    $("#addRules").css("display","block"); 
});
$("#addConfirm").click(function () {
    //document.write("1");
    $.ajax({
        url: "/firewall/add",
        type: "POST",
        data: '{"switcher1":"'+$("input[name='switcher1']").val()+'","switchlock":"'+$("#onoffswitch").is(':checked')+'","chain":"'+$("input[name='chain']:checked").val()+'","sip":"'+$("#sip").val()+'","dip":"'+$("#dip").val()+'","sport":"'+$("#sport").val()+'","dport":"'+$("#dport").val()+'","protocol":"'+$("input[name='protocol']:checked").val()+'","iintf":"'+$("#iintf").val()+'","ointf":"'+$("#ointf").val()+'","action":"'+$("#action").val()+'","a111":"'+$("#a111").val()+'"}',
        complete: function (e, xhr, settings) {
            if (e.status===401){
                console.log("登陆超时");
            }else if(e.status===406){
                console.log("输入格式有误");
            }else if(e.status===200){
                if(eval("("+e.responseText+")").result=="True"){
                    $("#firewallRules tr.rules").remove();
                    fwRules();
                    $("#addRules").css("display","none");
                }
            }else{
                console.log("服务器请求失败");
            }
        }
    })
});
$("#addCancel").click(function () {
    $("#addRules").css("display","none");
    $(".addInput").val("");
});
function detective() {
    $.json({
        url: "/firewall/ips",
        type: "GET",
        complete: function (e, xhr,setting) {
            if(e.status===401){
                console.log("登陆已超时");
            }else if (e.status===200){
                
            }else{
                console.log("服务器请求失败");
            }
        }
    })
}
$("#contentDet")
function getIps() {
    $.ajax({
        url:"/ips",
        type:"GET",
        complete:function (e,xhr,setting) {
            if(e.status===401){
                console.log("登陆已超时");
            }else if(e.status===200){
                var data=eval("("+e.responseText+")");
                $("#contentDet>div>p").remove();
                for(var i=0;i<data.result.length;i++){
                    if (i%2==0){
                        $("#contentDet>div").append("<p class='ips'>"+JSON.stringify(data.result[i])+"</p>");
                    }else{
                        $("#contentDet>div").append("<p class='bg'>"+JSON.stringify(data.result[i])+"</p>");
                    }
                }
            }
        }
    })
}
setInterval(getIps,5000);
$("#refresh3").click(function () {
    getIps();
});




