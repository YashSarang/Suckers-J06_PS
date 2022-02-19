<?php
require 'dtb.inc.php';

if (isset($_POST['login-submit'])) {

    $email = $_POST['login_email'];
    $pwd = $_POST['login_pwd'];

    if (empty($email) || empty($pwd)) {
        header("Location: ../login.php?error=emptyinput&login_email=".$email."&pwd=".$pwd);
        exit();
    } 

    else if(!preg_match("/^[a-zA-Z0-9.]*@\w+['ves.ac.in']*$/",$email)){
        header("Location: ../login.php?error=invalidmail");
        exit();
    }

    else {
        $sql = "SELECT * FROM users WHERE email=?;";
        $stmt = mysqli_stmt_init($conn);
        if (!mysqli_stmt_prepare($stmt, $sql)) {
            header("Location: ../login.php?error=sqlerror");
            exit();
        } 
        else {
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);
            if ($row = mysqli_fetch_assoc($result)) {
                $pwdCheck = password_verify($pwd, $row['pwd']);  // comparing password from user with the password in database

                if ($pwdCheck == 0) {
                    header("Location: ../login.php?error=wrongpwd");
                    exit();
                } else {
                    session_start();
                    $_SESSION['userId'] = $row['id'];
                    $_SESSION['userName'] = $row['username'];
                    header("Location: ../index.php?login=success");
                    exit();
                }
            } else {
                header("Location ../login.php?error=nodata");
            }
        }
    }
}

else if(isset($_POST['signup-submit']))
{
    $name = $_POST['name'];
    $email = $_POST['email'];
    $pwd = $_POST['pwd'];
    $year = $_POST['year'];
    $dept = $_POST['dept'];

    if (empty($name) || empty($pwd) || empty($email) || empty($dept)) {
        header("Location: ../login.php?error=emptyfields&name=".$name."&email=".$email);
        exit();
        } 

    else if(!preg_match("/^[a-zA-Z0-9.]*@\w+['ves.ac.in']*$/",$email)){
        header("Location: ../login.php?error=invalidmail&name=".$name);
        exit();
        }

    else {

            $sql = "SELECT email from users WHERE email=?";
            $stmt = mysqli_stmt_init($conn);
            if(!mysqli_stmt_prepare($stmt,$sql)){
                    header("Location: ../login.php?error=sqlerror");
                    exit();
            }
            
            else {
                mysqli_stmt_bind_param($stmt,"s",$email);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_store_result($stmt);
                $resutlCheck = mysqli_stmt_num_rows($stmt);
                if($resutlCheck > 0){
                    header("Location: ../login.php?error=mailexists&name=".$name);
                    exit();
                }
            }
    }

            $sql = "INSERT INTO users (username, email, pwd) VALUES (?, ?, ?);";
            $stmt = mysqli_stmt_init($conn);
            if (!mysqli_stmt_prepare($stmt, $sql)) {
                header("Location: ../login.php?error=sqlerror");
                exit();
            } 
            else {
                $hashedPwd = password_hash($pwd,PASSWORD_DEFAULT);

                mysqli_stmt_bind_param($stmt, "sss", $name,$email, $hashedPwd);
                mysqli_stmt_execute($stmt);
                header("Location: ../login.php?signup=success");
                exit();
            }

    mysqli_stmt_close($stmt);
    mysqli_close();
}

else{
    header("Location: ../login.php");
    exit();
}