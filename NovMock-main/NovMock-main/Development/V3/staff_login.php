<?php


session_start();
require_once("assets/dabco.php");
require_once("assets/staff_com.php");

if (isset($_SESSION["user"])) {
    $_SESSION['ERROR'] = 'ERROR: You are already logged in!';
    header("location: index.php");
    exit;
} elseif ($_SERVER["REQUEST_METHOD"] === 'POST') {
    $usr = staff_login(dabco_select(), $_POST);

    if ($usr && stfPassword($_POST['password'], $usr['password'])) {
        $_SESSION["user"] = true;
        $_SESSION["staffmessage"] = 'SUCCESS: User logged in successfully!';
        $_SESSION["stfid"] = $usr['staff_id'];
        S_audititor(dabco_insert(), $_SESSION['stfid'], "log", "User has been successfully logged in.");
        header("location: index.php");
        exit;
    } else {
        $_SESSION["staffmessage"] = 'ERROR: Wrong password!';
        header("location: index.php");
        exit;
    }
}

echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo"<title>Company Name</title>";
echo"<link href='css/styless.css' rel='stylesheet'>";
require_once "assets/header.php";
echo "</head>";
echo "<body>";

echo "<div id='main'>";

require_once "assets/header.php";
echo "<br>";
echo "</div>";
echo staff_message();

// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post'>";


// Email field
echo "<label for='email'>Email:  </label>";
echo "<br>";
echo "<input type='text' name='email' placeholder='Email'>";
echo "<br>";

// Password field
echo "<label for='password'>Password:  </label>";
echo "<br>";
echo "<input type='password' name='password' placeholder='Password'>"; // NOTE: Don't use default value in password fields
echo "<br>";


echo "<input type='submit' name='submit' value='Login'>";
echo "</form>";

echo "</div>";


echo"</body>";
require_once "assets/footer.php";
echo"</html>";
// complacently the access of the users