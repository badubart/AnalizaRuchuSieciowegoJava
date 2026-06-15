package analizasieci.windowsControls;

import analizasieci.Solution;
import analizasieci.packetCapture.PacketLookupRow;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

/**
 * Odpowiada za ładowanie widoków FXML i otwieranie okien aplikacji
 * (wybór interfejsu oraz podgląd pakietów), wraz z wstrzyknięciem do kontrolerów
 * wspólnego obiektu logiki {@link Solution}.
 */
public class WindowManager {

    /**
     * Otwiera okno wyboru interfejsu sieciowego.
     *
     * @param program obiekt logiki aplikacji przekazywany do kontrolera
     */
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
    /**
     * Otwiera okno podglądu pakietów i podpina obsługę zamknięcia okna
     * (pytanie o zapis przed wyjściem).
     *
     * @param program obiekt logiki aplikacji przekazywany do kontrolera
     */
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
            stage.setOnCloseRequest(controller::handleCloseRequest);
            stage.show();

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Could not load the packet lookup FXML file.");
        }
    }
}