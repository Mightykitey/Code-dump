<?php
session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!only_user(dabco_select(), $_POST['email'])) {

        try {
            if (new_user(dabco_insert(), $_POST)) {
                $_SESSION["user_message"] = 'User registered successfully!';
                //audititor(dabco_insert(), only_user(dabco_select(), $_POST['email']), "reg", "New user registered");
                header("Location:index.php?message=Registration Successful");
                exit;

            } else {
                $_SESSION["user_message"] = 'ERROR: You are not registered!';
            }
        } catch (Exception $e) {

        }
    } else {
        $_SESSION["user_message"] = 'ERROR: Email is already registered!';
    }
}

echo "<!DOCTYPE html>";
echo "<html>";

echo "<head>";
echo"<title>Home Assets Management</title>";
require_once "assets/header.php";
echo "</head>";
echo "<body>";

// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post' action=''>"; // Form posts back to the same page
echo "<br>";

echo"<label for=fname>First Name: </label>";
echo"<input type='text' name='fname' placeholder='First Name'>";
echo "<br>";

echo"<label for=lname>Last Name: </label>";
echo"<input type='text' name='lname' placeholder='Last Name'>";
echo "<br>";

echo"<label for=dob>Date Of Birth: </label>";
echo"<input type='text' name='dob' placeholder='Date Of Birth'>";
echo "<br>";

echo"<label for=email>Email: </label>";
echo"<input type='text' name='email' placeholder='Email'>";
echo "<br>";

echo"<label for=pwd>Password: </label>";
echo"<input type='password' name='pwd' placeholder='pwd'>";
echo "<br>";


echo"<input id='submit' type='submit' placeholder='Register'>";
echo "</form>";
echo "</div>";

echo"</body>";
require_once "assets/footer.php";
echo user_message();
echo"</html>";