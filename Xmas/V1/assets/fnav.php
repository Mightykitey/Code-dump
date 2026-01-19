<?php

// Link to an external CSS stylesheet (Note: There is a mistake in the tag — see correction below)
echo "<link rel='stylesheet' href='css/styless.css'>";

// Start of navigation bar container
echo "<div class='navi'>"; // A div with class 'navi' for styling the navigation area

// Begin the navigation menu
echo "<nav>";

// Start of the unordered list for navigation links
echo "<ul>";

// Navigation item: Link back to homepage/index
echo "<li><a href='index.php'>information</a></li>";


// End of the list
echo "</ul>";

// End of navigation
echo "</nav>";

// End of navigation container
echo "</div>";
