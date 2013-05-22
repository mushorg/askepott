<?php

$OP_ERROR = 0;
$OP_INFO = 1;
$OP_AUTH = 2;
$OP_PUBLISH = 3;
$OP_SUBSCRIBE = 4;

$ID = "";
$SECRET = "";
$CHAN = "";

$HOST = "";
$PORT = 20000;

function msghdr($op, $data){
    return pack("NC*", 5 + strlen($data), $op) . $data;
}

function msgpublish($ident, $chan, $data){
    global $OP_PUBLISH;
    return msghdr($OP_PUBLISH, pack("C*", strlen($ident)) . $ident . pack("C*",  strlen($chan)) . $chan . $data);
}

function msgsubscribe($ident, $chan){
    global $OP_SUBSCRIBE;
    return msghdr($OP_SUBSCRIBE, pack("C*", strlen($ident)) . $ident . $chan);
}

function msgauth($rand, $ident, $secret){
    $hash = sha1($rand . $secret, true);
    global $OP_AUTH;
    return msghdr($OP_AUTH, pack("C*", strlen($ident)) . $ident . $hash);
}

function hp_unpack($pattern, $msg){
    return unpack($pattern, $msg);
}

function read_feed($fp){
    $buf = fgets($fp, 5);
    $len = hp_unpack("N1mlength", $buf);
    $buf = fgets($fp, $len["mlength"] - 3);
    $data = hp_unpack("C1opcode/A*", $buf);
    var_dump($data);
}

function hpfeeder($payload){
    $fp = fsockopen($HOST, $PORT, $errno, $errstr, 5);
    $buf = fgets($fp, 5);
    $len = hp_unpack("N1mlength", $buf);
    $buf = fgets($fp, $len["mlength"] - 3);
    $data = hp_unpack("C1opcode/C1next/A4id/A*nonce", $buf);
    fwrite($fp, msgauth($data["nonce"], $ID, $SECRET));
    fwrite($fp, msgpublish($ID, $CHAN, $payload));
    fflush($fp);
    fclose($fp);
}

hpfeeder("foobar");

?>