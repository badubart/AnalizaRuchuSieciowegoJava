package analizasieci.windowsControls;

import analizasieci.Solution;
import analizasieci.packetCapture.PacketLookupRow;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class WindowManager {

    public void showDevSelectWindow(Solution program) {
        try {
            // Load the FXML file
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/fxmlWindows/devSelectWindow.fxml"));
            Parent root = fxmlLoader.load();

            DevSelectWindowController controller = fxmlLoader.getController();
            controller.setProgram(program);


            Stage stage = new Stage();
            stage.setTitle("Wybór interfejsu");
            stage.setMinHeight(400);
            stage.setMinWidth(500);

            stage.setScene(new Scene(root));
            stage.show();

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Could not load the FXML file.");
        }
    }
    public void showPacketLookupWindow(Solution program){
        try {
            // Make sure the path matches your project structure
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/fxmlWindows/packetLookup.fxml"));

            Parent root = fxmlLoader.load();
            PacketLookupWindowController controller = fxmlLoader.getController();
            controller.setProgram(program);

            Stage stage = new Stage();
            stage.setTitle("Podgląd pakietów");
            stage.setScene(new Scene(root));
            stage.setMinHeight(400);
            stage.setMinWidth(500);
            stage.show();

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Could not load the packet lookup FXML file.");
        }
    }
}