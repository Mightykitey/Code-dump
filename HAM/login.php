<?php
session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";

if (isset($_SESSION["usrid"])) {
    $_SESSION['ERROR'] = 'ERROR: You are already logged in!';
    header("location: index.php");
    exit;
} elseif ($_SERVER["REQUEST_METHOD"] === 'POST') {
    $usr = login(dabco_insert(), $_POST['email']);

    if ($usr && password_verify($_POST["password"], $usr["password"])) { // verifies the password is matched
        $_SESSION["userid"] = $usr["user_id"];
        $_SESSION['user_message'] = "SUCCESS: viewer Successfully Logged In";
        audtitor(dabco_insert(), $_SESSION["userid"], "log", "viewer has successfully logged in");
        header("location:index.php");  //redirect on success
        exit;
    } elseif (!$usr) {
        $_SESSION['user_message'] = "ERROR: viewer not found";
        header("Location: login.php");
        exit; // Stop further execution
    } else {
        $_SESSION['user_message'] = "ERROR: viewer login passwords not match";
        if ($usr["userid"]) {
            audtitor(dabco_insert(), $usr["userid"], "flo", "User has unsuccessfully logged in");
        }
        header("Location: login.php");
        exit; // Stop further execution

    }

}

echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo "<title>Home Assets Management</title>";

require_once "assets/header.php";
echo "</head>";

// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post' action=''>"; // Form posts back to the same page
echo "<br>";

// Email field
echo "<label for='email'>Email:  </label>";
echo "<br>";
echo "<input type='text' name='email' placeholder='Email'>";
echo "<br>";

// Password field
echo "<label for='pwd'>Password:  </label>";
echo "<br>";
echo "<input type='password' name='pwd' placeholder='Password'>"; // NOTE: Don't use default value in password fields
echo "<br>";

echo "<input id='submit' type='submit' placeholder='Register'>";
echo "</form>";
echo "</div>";


require_once "assets/footer.php";
echo user_message();
echo "</body>";
echo "</html>";


