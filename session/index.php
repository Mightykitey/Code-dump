<?php

session_start();/*each page that needs a session, not file*/

require_once "asssets/commonfunk.php"; //require_once only happen once anywhere

if ($_SERVER["REQUEST_METHOD"] === 'POST') { // super global veurable
   // echo $_POST["message"];
    $_SESSION['msg'] = $_POST["message"];

}

echo"<!doctype html>";

echo"<html>";

echo"<head>";
echo"<title>session work</title>";
echo"<link rel='css/styles.css' rel='stylesheet'>";
echo"</head>";

    echo"<body>";



    echo "<div class='content'>";


    echo usr_msg();



    echo"<h1>session work</h1>"; /*take user input and stores it somewhere else*/


            echo "<form method='post' action=''>";

            echo"<label=''>Please enter</label>";

            echo"<br>";
            echo"<input type='text' name='message' id='msg' placeholder='message'>";

            echo"<br>";
            echo"<label='lgn'>sudmit</label>";

            echo"<br>";
            echo "<input  type='submit' name='submit'  value='submit'>";

        echo"</form>";


    echo"</body>";

    echo"</html>";

