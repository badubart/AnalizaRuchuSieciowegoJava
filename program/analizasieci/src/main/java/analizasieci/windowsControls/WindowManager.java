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
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/fxmlWindows/devSelectWindow.fxml"));
            Parent root = fxmlLoader.load();

            DevSelectWindowController controller = fxmlLoader.getController();
            controller.setProgram(program);


            Stage stage = new Stage();
            stage.setTitle("Wybór interfejsu");
            stage.setMinHeight(500);
            stage.setMaxHeight(800);
            stage.setMinWidth(640);
            stage.setMaxWidth(640);

            stage.setScene(new Scene(root));
            stage.show();
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Could not load the FXML file.");
        }
    }
    public void showPacketLookupWindow(Solution program){
        try {
            FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/fxmlWindows/packetLookup.fxml"));

            Parent root = fxmlLoader.load();
            PacketLookupWindowController controller = fxmlLoader.getController();
            controller.setProgram(program);

            Stage stage = new Stage();
            stage.setTitle("Podgląd pakietów");
            stage.setScene(new Scene(root));
            stage.setMinHeight(600);
            stage.setMaxHeight(800);
            stage.setMinWidth(1120);
            stage.setMaxWidth(1120);
            stage.show();

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Could not load the packet lookup FXML file.");
        }
    }
}