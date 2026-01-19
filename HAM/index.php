<?php
session_start();/*each page not file*/

require_once "assets/commonfunk.php"; //require_once only happen once anywhere

if ($_SERVER["REQUEST_METHOD"] === 'POST') { // super global veurable
    // echo $_POST["message"];
    $_SESSION['msg'] = $_POST["message"];

}

echo"<!doctype html>";

echo"<html>";

echo"<head>";

echo"<title>Home Assets Management</title>";
require_once "assets/header.php";
echo"</head>";

echo"<body>";
echo "<div class='content'>";



echo"<h1>Hello</h1>";

/*echo "<form method='post' action=''>";*/

echo"</body>";
require_once "assets/footer.php";
echo"</html>";

?>


