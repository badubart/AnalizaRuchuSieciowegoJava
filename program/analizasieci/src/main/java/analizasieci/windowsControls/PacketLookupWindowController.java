package analizasieci.windowsControls;

import analizasieci.Solution;
import analizasieci.packetCapture.MyPacket;
import analizasieci.packetCapture.PacketLookupRow;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.text.Font;
import javafx.stage.Stage;

import java.util.Map;

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
    @FXML private TextArea hexDump;
    @FXML private Button button1;
    @FXML private MenuItem fileQuit;

    private final ObservableList<PacketLookupRow> packetData = FXCollections.observableArrayList();

    public void setProgram(Solution program) {
        this.program = program;
        startCaptureThread();
    }

    @FXML
    public void initialize() {
        System.out.println("tesst");
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
        protocolTree.setShowRoot(false);
        if(hexDump != null) {
            hexDump.setFont(Font.font("Consolas",12));
            hexDump.setEditable(false);
        }
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
        MyPacket packet = row.getPacket();
        if (packet == null){
            System.out.println("Pakiet NULL");
            return;
        }

        // 1. AKTUALIZACJA DRZEWA WARSTW (TreeView)
        TreeItem<String> rootItem = new TreeItem<>("Packet");

        // Przechodzimy przez wszystkie warstwy (np. Ethernet, IPv4, TCP)
        for (ProtocolLayer layer : packet.getLayers()) {

            // Tworzymy główną gałąź dla protokołu (np. "Internet Protocol Version 4 (IPv4)")
            TreeItem<String> layerNode = new TreeItem<>(layer.getProtocolName());
            layerNode.setExpanded(true); // Domyślnie rozwijamy gałęzie

            // Dodajemy szczegóły nagłówka jako liście
            for (Map.Entry<String, String> entry : layer.getFields().entrySet()) {
                // Sklejamy klucz z wartością (np. "Source IP: 192.168.1.1")
                TreeItem<String> fieldNode = new TreeItem<>(entry.getKey() + ": " + entry.getValue());
                layerNode.getChildren().add(fieldNode);
            }

            rootItem.getChildren().add(layerNode);
        }

        // Aktualizujemy drzewo w GUI
        protocolTree.setRoot(rootItem);

        // 2. AKTUALIZACJA ZRZUTU SZESNASTKOWEGO (Hex Dump)
        if (hexDump != null) {
            hexDump.setText(packet.getHexDump());
        }
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