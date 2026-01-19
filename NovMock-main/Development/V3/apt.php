<?php


session_start(); // Start the session for this page to allow session variables (like flash messages)


// Include required PHP files only once
require_once "assets/commonfunk.php"; // Common utility functions
require_once "assets/dabco.php";      // Database connection functions

if (!isset($_SESSION["usrid"])) {
    $_SESSION['usermessage'] = "Error: You are not logged in.";
    header("Location: login.php");
    exit;
} else if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (isset($_POST['appdelete'])) {
        try {
            if (cancel_apt(dabco_delete(), $_POST['aptid'])) {
                $_SESSION['usermessage'] = "SUCCESS: Your booking has been cancelled.";
            } else {
                $_SESSION['usermessage'] = "ERROR.";
            }

        } catch (PDOException $e) {
            $_SESSION['message'] = "ERROR: Your booking has not been cancelled.";
        } catch (Exception $e) {
            $_SESSION['message'] = "ERROR: Your booking has not been cancelled.";
        }

    } else if (isset($_POST['appdchange'])) {
        $_SESSION['aptid'] = $_POST['aptid'];
        header("Location: alt_book.php");
        exit;
    }
}

// Check if the form was submitted using the POST method

// Output the HTML document
echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo "<title>Rolsa Technologies</title>";
require_once "assets/header.php";
echo "</head>";

echo "<body>";


echo "<h2>Your Booking</h2>";

echo "<div class='container'>";


$apts = apt_getter(dabco_select());
if (!$apts) {
    echo "no apts found";
} else {

    echo "<table id='booking'>";

    foreach ($apts as $apt) {
        if ($apt['job'] = "ins") {
            $role = 'Inspector';
        } else if ($apt['role'] = "egr") {
            $role = "Engineer";
        }
    }
    echo "<form action='' method='post'>";

    echo "<tr>";
    echo "<td>Date:   " . date('M d, Y @ h:i A', $apt['appdate']) . "</td>";
    echo "<td>Made on:    " . date('M d, Y @ h:i A', $apt['bookdon']) . "</td>";
    echo "<td>With:    " . $role . " " . $apt['fname'] . " " . $apt['lname'] . " " . "</td>";
    echo "<td><input type='hidden' name='aptid' value=" . $apt['bookid'] . ">
    <input type='submit' name='appdelete' value='Cancel Apt'/>
    <input type='submit' name='appdchange' value='Change Apt'/></td>";

    echo "</tr>";
    echo "</form>"; // creating a for each table
}


echo "</table>";

echo "</div>";

echo user_message();

echo"</body>";
require_once "assets/footer.php";
echo "</html>";
