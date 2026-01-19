<?php

session_start();
require_once("assets/dabco.php");
require_once("assets/staff_com.php");


if (isset($_SESSION["user"])) {
    $_SESSION['ERROR'] = 'ERROR: You are already logged in!';
    header("location: index.php");
    exit;
}

elseif ($_SERVER["REQUEST_METHOD"] === 'POST') {
    $usr = staff_login(dabco_select(), $_POST);

    if ($usr && stfPassword($_POST['password'],$usr['password'])) {
        $_SESSION["user"]=true;
        $_SESSION["staffmessage"] = 'SUCCESS: User logged in successfully!';
        $_SESSION["stfid"] = $usr['staff_id'];
        S_audititor(dabco_insert(), $_SESSION['stfid'], "log", "User has been successfully logged in.");
        header("location: index.php");
        exit;
    }else{
        $_SESSION["staffmessage"] = 'ERROR: Wrong password!';
        header("location: index.php");
        exit;
    }
}

echo"<!doctype html>";
echo"<html>";

echo"<head>";
echo"<title>Staff Login page</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";
echo"<img src='images/primary_oaks_surgery.jpg' alt='primary oaks surgery'>";
echo"</head>";
echo"<body>";

echo "<div id='main'>";
echo"<h1>Login page</h1>";
require_once 'assets/nav.php';
echo"<br>";
echo"</div>";
echo staff_message();

echo "<div class='content'>";
echo"<form method='post'>";


// Email field
echo "<label for='email'>Email:  </label>";
echo"<br>";
echo "<input type='text' name='email' placeholder='Email'>";
echo "<br>";

// Password field
echo "<label for='password'>Password:  </label>";
echo "<br>";
echo "<input type='password' name='password' placeholder='Password'>"; // NOTE: Don't use default value in password fields
echo "<br>";


echo"<input type='submit' name='submit' value='Login'>";
echo"</form>";

echo"</div>";




echo"</body>";

echo"</html>";

// complacently the access of the users