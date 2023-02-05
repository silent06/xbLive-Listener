<!DOCTYPE html>
<html>

<head>

</head>



<?php




  $target_dir = "/var/www/html/xbLive/admin/";
  $newFileName = $target_dir .'nokvChecker'.'.'. pathinfo($_FILES["my-file"]["name"] ,PATHINFO_EXTENSION); //get the file extension and append it to the new file name
  $uploadOk = 1;
  $imageFileType = pathinfo($_FILES["my-file"]["name"] ,PATHINFO_EXTENSION);
  // Check if image file is a actual image or fake image
  if(isset($_POST["submit"])) {
      //$check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
      /*if($check !== false) {
          echo "File is an image - " . $check["mime"] . ".";
          $uploadOk = 1;
      } else {
          echo "File is not an image.";
          $uploadOk = 0;
      }*/
      $uploadOk = 1;
  }else {

    $uploadOk = 0;
  }

  // Check if $uploadOk is set to 0 by an error
  if ($uploadOk == 0) {
      echo "Sorry, your file was not uploaded.";
  // if everything is ok, try to upload file
  } else {
      if (move_uploaded_file($_FILES["my-file"]["tmp_name"],  $newFileName)) {
          echo "The file ". basename( $_FILES["my-file"]["name"]). " has been uploaded.";
          //get current file directory
          $old_path = getcwd();
          //switch to xbLive dictory 
          chdir('/var/www/html/xblive/');
          //run cmd/shell commands
          //$output = shell_exec('/bin/sh script.sh');
          //chdir($old_path);
          //echo "<pre>$output</pre>";
          //header("refresh: 1; url = status.php");
  
      } else {
          echo "Sorry, there was an error uploading your file.";
      }
  }

?>
</html>
