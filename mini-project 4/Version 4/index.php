<?php
// Start the session to allow session variables to be used across pages
session_start();

// Include external PHP file that contains common functions (only once to avoid redeclaration errors)
require_once "assets/commonfunk.php";

// Include another PHP file, likely for database connection functions
require_once "assets/dabco.php";

// Output the HTML document declaration
echo "<!doctype html>";

echo "<html>"; // Open HTML tag

echo "<head>"; // Open head section
echo "<title>Primary Oaks Surgery</title>"; // Set the title of the page (appears in browser tab)
echo "<link href='css/styles.css' rel='stylesheet'>"; // Link to an external CSS file for styling
echo"<img src='images/primary_oaks_surgery.jpg' alt='primary oaks surgery'>";
echo "</head>"; // Close head section

echo "<body>"; // Start of body content

echo "<div id='main'>"; // Start main content container with ID 'main'
echo "<h1>Primary Oaks Surgery</h1>"; // Main heading of the page
require_once "assets/nav.php"; // Include navigation menu (likely a list of links)
echo "</div>"; // Close the main container div

echo "<p>Hello world</p>"; // Output a simple paragraph for demonstration or testing

// Attempt to connect to the database using a function (likely defined in dabco.php)
echo user_message();

echo "</body>"; // Close body tag

//echo "</html>"; // Close HTML tag
//?>
<!---->
<!--// epoch time is simple and easier, date and time is stored in one coloum, and it has a high percision-->
//