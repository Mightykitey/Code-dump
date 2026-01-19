<?php

session_start(); // Start the session for this page to allow session variables (like flash messages)

// Include required PHP files only once
require_once "assets/staff_com.php"; // Common utility functions
require_once "assets/dabco.php";      // Database connection functions

// Check if the form was submitted using the POST method
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!only_staff(dabco_select(), $_POST['email'])) {

        if (new_staff(dabco_insert(), $_POST)) {
            $_SESSION["staffmessage"] = 'staff registered successfully!';
            S_audititor(dabco_insert(), only_staff(dabco_select(), $_POST['email']), "reg", "New doctor registered");
            header("Location:index.php?message=Registration Successful");
            exit;
        } else {
            $_SESSION["staffmessage"] = 'ERROR: You are not registered!';
        }
    } else {
        $_SESSION["staffmessage"] = 'ERROR: Email is already registered!';
    }
}
// Output the HTML document
echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo"<title>Rolsa Technologies</title>";
echo"<link href='css/styless.css' rel='stylesheet'>";
require_once "assets/header.php";
echo "</head>";

echo "<body>";

echo "</div>";

echo staff_message();
// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post' action=''>"; // Form posts back to the same page
echo "<br>";

// First Name field
echo "<label for='fname'>Name:  </label>";
echo "<br>";
echo "<input type='text' name='fname' placeholder='First Name'>"; // NOTE: value should be empty or placeholder
echo "<br>";

// Last Name field
echo "<label for='lname'>Surname:  </label>";
echo "<br>";
echo "<input type='text' name='lname' placeholder='last Name'>";
echo "<br>";

echo "<label for='egr'>Engineer:  </label>";
echo "<br>";
echo "<input type='radio' name='job' placeholder='egr'>";
echo "<br>";

echo "<label for='ins'>Inspector:  </label>";
echo "<br>";
echo "<input type='radio' name='job' placeholder='ins'>";
echo "<br>";

echo "<label for='adm'>Admin:  </label>";
echo "<br>";
echo "<input type='radio' name='job' placeholder='adm'>";
echo "<br>";

// Email field
echo "<label for='email'>Email:  </label>";
echo "<br>";
echo "<input type='text' name='email' placeholder='Email'>";
echo "<br>";

// Password field
echo "<label for='password'>Password:  </label>";
echo "<br>";
echo "<input type='password' name='pwd' placeholder='Password'>"; // NOTE: Don't use default value in password fields
echo "<br>";

// Submit button is missing — should be added to make the form work
echo "<input type='submit' placeholder='Register'>";

echo "</form>";
echo "</div>";

echo"</body>";
require_once "assets/footer.php";
echo"</html>";