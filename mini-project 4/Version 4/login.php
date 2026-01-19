<?php

session_start();
require_once("assets/dabco.php");
require_once("assets/commonfunk.php");


if (isset($_SESSION["patid"])) {
    $_SESSION['ERROR'] = 'ERROR: You are already logged in!';
    header("location: index.php");
    exit;
}elseif($_SERVER["REQUEST_METHOD"] === 'POST') {
    $usr = login(dabco_insert(), $_POST['email']);

    if ($usr && password_verify($_POST['pwd'],$usr['pwd'])) {
        $_SESSION["patid"]=$usr['patient_id'];
        $_SESSION["usermessage"] = 'SUCCESS: User logged in successfully!';
        audititor(dabco_insert(), $_SESSION['patid'], "log", "User has been successfully logged in.");
        header("location: index.php");
        exit;
    }else if(!$usr){
        $_SESSION["usermessage"] = 'ERROR: No user found!';
        header("location: index.php");
        exit;
    }
}

echo"<!doctype html>";
echo"<html>";

echo"<head>";
echo"<title>Login page</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";
echo"<img src='images/primary_oaks_surgery.jpg' alt='primary oaks surgery'>";
echo"</head>";
echo"<body>";

echo "<div id='main'>";
echo"<h1>Login page</h1>";
require_once 'assets/nav.php';
echo"<br>";
echo"</div>";


echo "<div class='content'>";
echo"<form method='post'>";


// Email field
echo "<label for='email'>Email:  </label>";
echo"<br>";
echo "<input type='text' name='email' placeholder='Email'>";
echo "<br>";

// Password field
echo "<label for='pwd'>Password:  </label>";
echo "<br>";
echo "<input type='password' name='pwd' placeholder='Password'>"; // NOTE: Don't use default value in password fields
echo "<br>";


echo"<input type='submit' name='submit' value='Login'>";
echo"</form>";

echo"</div>";

echo user_message();


echo"</body>";

echo"</html>";

// complacently the access of the users