<?php
session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!only_user(dabco_select(), $_POST['email'])) {

        if (new_user(dabco_insert(), $_POST)) {
            $_SESSION["usermessage"] = 'User registered successfully!';
            audit(dabco_insert(),only_user(dabco_select(), $_POST['email']),"reg", "New user registered" );
            header("Location:index.php?message=Registration Successful");
            exit;

        } else {
            $_SESSION["usermessage"] = 'ERROR: You are not registered!';
        }
    } else {
        $_SESSION["usermessage"] = 'ERROR: Email is already registered!';
    }
}

echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo"<title>Rolsa Technologies</title>";
echo"<link href='css/styless.css' rel='stylesheet'>";
require_once "assets/header.php";
echo "</head>";
echo "<bod>";





echo"</body>";
require_once "assets/footer.php";
echo"</html>";
