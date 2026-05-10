package analizasieci.windowsControls;

import analizasieci.Solution;
import analizasieci.packetCapture.PacketLookupRow;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.Stage;

public class PacketLookupWindowController {

    private Solution program;

    @FXML private TableView<PacketLookupRow> packetList;
    @FXML private TableColumn<PacketLookupRow, Integer> colNr;
    @FXML private TableColumn<PacketLookupRow, String> colSource;
    @FXML private TableColumn<PacketLookupRow, String> colDestination;
    @FXML private TableColumn<PacketLookupRow, String> colProtocol;
    @FXML private TableColumn<PacketLookupRow, Integer> colLength;
    @FXML private TableColumn<PacketLookupRow, String> colInfo;

    @FXML private TreeView<String> protocolTree;

    @FXML private Button button1;
    @FXML private MenuItem fileQuit;

    private final ObservableList<PacketLookupRow> packetData = FXCollections.observableArrayList();

    public void setProgram(Solution program) {
        this.program = program;
        startCaptureThread();
    }

    @FXML
    public void initialize() {
        colNr.setCellValueFactory(new PropertyValueFactory<>("id"));
        colSource.setCellValueFactory(new PropertyValueFactory<>("source"));
        colDestination.setCellValueFactory(new PropertyValueFactory<>("destination"));
        colProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colLength.setCellValueFactory(new PropertyValueFactory<>("length"));
        colInfo.setCellValueFactory(new PropertyValueFactory<>("info"));

        packetList.setItems(packetData);

        packetList.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                updateDetailsArea(newSelection);
            }
        });

        button1.setOnAction(event -> handleBackAction());

        if (fileQuit != null) {
            fileQuit.setOnAction(event -> System.exit(0));
        }

        TreeItem<String> rootItem = new TreeItem<>("Root");
    }

    private void startCaptureThread() {
        Thread captureThread = new Thread(() -> {
            program.listeningLoop(this::addPacketToTable);
        });

        captureThread.setDaemon(true);
        captureThread.start();
    }

    private void addPacketToTable(PacketLookupRow row) {
        Platform.runLater(() -> {
            packetData.add(row);

        });
    }

    private void updateDetailsArea(PacketLookupRow row) {

    }

    private void handleBackAction() {
        program.stopListening();

        try {
            WindowManager manager = new WindowManager();
            manager.showDevSelectWindow(program);

            Stage stage = (Stage) button1.getScene().getWindow();
            stage.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}