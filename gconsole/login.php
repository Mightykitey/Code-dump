<?php

session_start();
require_once("assets/dabco.php");
require_once("assets/commonfunk.php");


if (isset($_SESSION["user"])) {
    $_SESSIOM['usermessage'] = 'ERROR: You are already logged in!';
    header("location: index.php");
    exit;
}

elseif ($_SERVER["REQUEST_METHOD"] === 'POST') {
    $usr = login(dabco_insert(), $_POST);

    if ($usr && password_verify($_POST['password'],$usr['password'])) {
        $_SESSION["user"]=true;
        $_SESSION["usermessage"] = 'SUCCESS: User logged in successfully!';
        $_SESSION["UserID"] = $usr['USER_id'];
        header("location: index.php");
        exit;
    }else{
        $_SESSION["usermessage"] = 'ERROR: Wrong password!';
        header("location: index.php");
        exit;
    }
}

echo"<!doctype html>";
echo"<html>";

echo"<head>";
echo"<title>Consoles</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";
echo"</head>";
echo"<body>";

echo"<div class='container'>";
echo"<h1>Consoles</h1>";
require_once 'assets/nav.php';
echo"<br>";


    echo"<div class='form-container'>";
        echo"<form method='post' action='login.php'>";

            echo"<label for='username'>Username: </label>";
            echo"<br>";
            echo"<input type='text' name='username' placeholder='Username'>";
            echo"<br>";

            echo"<label for='password'>Password: </label>";
            echo"<br>";
            echo"<input type='password' name='password' placeholder='Password'>";
            echo"<br>";

            echo"<label for='submit'>submit: </label>";
            echo"<br>";
            echo"<input type='submit' name='submit' value='Login'>";
        echo"</form>";

    echo"</div>";


      echo"<img src='images/Dreamcast.png' id='DreamCast' alt='Dreamcast'>";



      echo "<img src='images/3DS.png' id='DS' alt='3DS'>";




echo"</body>";

echo"</html>";

// complacently the access of the users
