<?php

session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";


echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo "<title>Rolsa Technologies</title>";
echo "<link href='css/styless.css' rel='stylesheet'>";
require_once "assets/header.php";
echo "</head>";

// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post' action=''>"; // Form posts back to the same page
echo "<br>";


echo"<input id='submit' type='submit' placeholder='Register'>";
echo "</form>";
echo "</div>";

require_once "assets/footer.php";
echo user_message();
echo "</body>";
echo "</html>";
