package analizasieci.windowsControls;

import analizasieci.Solution;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuItem;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import java.util.stream.Collectors;

/**
 * Kontroler okna wyboru interfejsu sieciowego.
 * Wyświetla listę dostępnych interfejsów; podwójne kliknięcie wybiera interfejs
 * i otwiera okno podglądu pakietów.
 */
public class DevSelectWindowController {
    Solution program;
    @FXML
    private ListView<String> devList;

    @FXML
    private Text welcomeText;

    @FXML
    private MenuItem fileQuit;

    /**
     * Wstrzykuje logikę aplikacji i wypełnia listę interfejsów.
     *
     * @param program obiekt logiki aplikacji
     */
    public void setProgram(Solution program) {
        this.program = program;
        setup();
    }

    /** Inicjalizacja JavaFX: podpięcie obsługi podwójnego kliknięcia i pozycji menu. */
    public void initialize() {
        devList.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2 && (!devList.getSelectionModel().isEmpty())) {
                String selectedDevice = devList.getSelectionModel().getSelectedItem();
                int selectedId = devList.getSelectionModel().getSelectedIndex();
                program.selectNetworkInterface(selectedId);
                openPacketLookupWindow();
            }
        });
        if (fileQuit != null) {
            fileQuit.setOnAction(event -> System.exit(0));
        }
    }
    void setup(){
        if (program != null && program.getDevices() != null) {
            ObservableList<String> devices = FXCollections.observableArrayList(program.getDevices().stream().map(x -> x.getDescription()).collect(Collectors.toList()));
            devList.setItems(devices);
        }
    }

    private void openPacketLookupWindow() {
        try {
            WindowManager windowManager = new WindowManager();

            windowManager.showPacketLookupWindow(program);

            Stage currentStage = (Stage) devList.getScene().getWindow();
            currentStage.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to open packet lookup window.");
        }
    }

}