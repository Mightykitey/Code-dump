<?php

function usr_msg()
{


    if (isset($_SESSION["msg"])) { // checks for the session variable being set

        if (str_contains($_SESSION["msg"], "ERROR")) {
            $msg = "<div id='error'> USER MESSAGE: " . $_SESSION["msg"] . "</div>";
        } else {
            $msg = "<div id='cor'> USER MESSAGE: " . $_SESSION["msg"] . "</div>";
        }

        $_SESSION["msg"] = '';
        unset($_SESSION["msg"]); //
        return $msg;
// = 'USER MESSAGE: ' . $_SESSION["msg"]; // echos out the stored error from session
    } else {
        return "";
    }
}

