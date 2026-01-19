<?php
echo"<html>";
echo"<head>";
    echo"<title>GibJohn home</title>";
    echo"<link rel='stylesheet' href='css/style.css'>";
echo"</head>";

    echo"<body>";
        echo "<img id='logo' src='images/logo.jpg'  alt='logo' >";


    echo "  <h1>Leave a Review</h1>";

    echo "<form method='post' action=''>";
        echo "<table>";

            echo "<tr><td>";
            echo "<label for=\"name\">Your Name:</label>";
            echo"<br>";
            echo "<input type=\"text\" id=\"name\" name=\"name\" required>";
            echo "</tr></td>";


            echo "<tr><td>";
            echo "    <label for=\"rating\">Rating (1-5):</label>";
            echo"<br>";
            echo "    <input type=\"number\" id=\"rating\" name=\"rating\" min=\"1\" max=\"5\" required>";
            echo "</tr></td>";

            echo "<tr><td>";
            echo "    <label for=\"review\">Your Review:</label>";
            echo"<br>";
            echo "    <textarea id=\"review\" name=\"review\" rows=\"4\" cols=\"50\" required></textarea>";
            echo "</tr></td>";

            echo "<tr><td>";
            echo "    <button type=\"submit\">Submit Review</button>";
            echo "</tr></td>";
        echo "</table>";
    echo "  </form>";
echo"<img src='images/ClassWork.jpg' alt='ClassWork' >";
echo"<br>";
echo"<a href='index.php'>Return back</a>";

echo"</body>";
echo"</html>";

